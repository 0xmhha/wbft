package node

import (
	"bytes"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type queuedSourceProbe struct {
	transport.Transport
	target  transport.WritePeer
	attempt transport.SendAttempt
}

func (p *queuedSourceProbe) WritePeers() []transport.WritePeer {
	return []transport.WritePeer{p.target}
}
func (p *queuedSourceProbe) SendWrite(_ transport.WritePeer, _ uint64, _ []byte, attempt transport.SendAttempt, _ func(transport.WriteReceipt)) transport.SendResult {
	p.attempt = attempt
	return transport.QueueFull // Local fixture has no physical writer or frame.
}

func TestSessionFrameRecorderOriginalReservationAndQueueRefusal(t *testing.T) {
	fs := fsys.NewMem()
	policy := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/session-node", Synchronous: true}, journal.Identity{Run: "original-node-recorder", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: policy}}})
	if err != nil {
		t.Fatal(err)
	}
	legacy := newFrameRecorder(w, fixedClock{}, 0)
	if _, ok := any(legacy).(transport.SessionObserver); ok {
		t.Fatal("default recorder acquired new stream semantics")
	}
	rec := newSessionFrameRecorder(w, fixedClock{}, 0)
	target := transport.WritePeer{Addr: types.Address{7}, Session: transport.NewWriteSession()}
	rec.ObservedSession(target)
	probe := &queuedSourceProbe{target: target}
	wrapped := recordedWriteTransport{Transport: probe, WriteSender: probe, rec: rec}
	if _, ok := any(wrapped).(transport.CacheObserver); ok {
		t.Fatal("new sender acquired legacy cache semantics")
	}
	key, err := ecdsa.PrivateKeyFromBytes(testKey(0))
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(1)}}
	signing, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	limits := transport.WriteLedgerOptions{Pending: 8, PerPeer: 4, KeyWithCode: true, Trace: rec}
	dedup, err := transport.NewDedup(wrapped, transport.DedupOptions{KeyWithCode: true, RecordAfterSend: true, CompletedWrites: &limits})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := validator.NewSet([]types.Address{target.Addr}, [][]byte{nil}, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	dedup.Gossip(vs, uint64(m.Code), raw, event.CauseRetry)
	source, ok := probe.attempt.WriteSource()
	if !ok || source.WriterRun != "original-node-recorder" {
		t.Fatal("factory lost actual reservation", source)
	}
	// Direct observer probes below test value construction and byte ownership,
	// not actual network completion. SDK tests supply the real I/O evidence.
	original := bytes.Clone(raw)
	rec.ReceivedSession(target, uint64(m.Code), len(raw), raw, transport.OfferQueued, 1, nil)
	rec.attemptSequence.Store(^uint64(0))
	dedup.Gossip(vs, uint64(m.Code), raw, event.CauseRetry)
	if probe.attempt != (transport.SendAttempt{}) || rec.attemptSequence.Load() != ^uint64(0) {
		t.Fatal("exhausted counter reused an observation")
	}
	raw[0] ^= 1 // Only the caller's local buffer changes, after the callback.
	dedup.CloseCompletedWrites()
	target.Session.Close()
	rec.EndedSession(target, transport.SessionRemoved)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(fs, "/session-node")
	if err != nil {
		t.Fatal(err)
	}
	prepared, refused, inbound := false, false, 0
	for _, record := range records {
		switch r := record.Body.(type) {
		case *journal.WriteCacheRec:
			if r.Transition.Action == transport.WritePrepare && r.Transition.Request == source.Request && r.Transition.Ledger == source.Ledger {
				prepared = true
			}
			if r.Transition.Action == transport.WriteQueueResult && r.Transition.Queue == transport.QueueFull && r.Transition.PendingAfter == 0 {
				refused = true
			}
		case *journal.MsgRec:
			if r.Dir == journal.Out {
				t.Fatal("queue refusal fabricated physical frame")
			}
			inbound++
			if r.Dedup != nil || r.IO != nil || r.Session == nil || r.Session.Run != source.WriterRun || !bytes.Equal(r.Payload, original) {
				t.Fatal("diagnostic source borrowed legacy state or mutable bytes")
			}
		}
	}
	if !prepared || !refused || inbound != 1 {
		t.Fatal("actual reservation or local queue transition missing", prepared, refused, inbound)
	}
	check, err := journal.CheckWriteIOSources(records, journal.WriteIOCheckLimits{Records: 1000, Ledgers: 4, Reordered: 16, Sessions: 8, Requests: 16, Frames: 16})
	if err != nil || check.Status != "consistent" || check.Writes != 0 || check.Reservations != 2 || check.PhysicalStatus != "unavailable" {
		t.Fatal("queue-only source was mistaken for physical writes", check, err)
	}
}
