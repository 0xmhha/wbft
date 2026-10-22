package main

import (
	"crypto/sha256"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type commandWriteSource struct {
	writer journal.Writer
	owner  *transport.AttemptOwner
}

func (s commandWriteSource) AttemptOwner() *transport.AttemptOwner { return s.owner }
func (s commandWriteSource) CaptureRun() string                    { return "command-source" }
func (s commandWriteSource) ObserveWriteTransition(t transport.WriteTransition) {
	s.writer.Put(journal.Record{Body: &journal.WriteCacheRec{Transition: t}})
}

// This is a local command/metadata fixture, not a network execution. The SDK
// adapter tests separately compare the same checker with genuine WriteMsg I/O.
func commandWriteIOFixture(t *testing.T, fs fsys.FS, dir string, differentRecordedCode bool) {
	t.Helper()
	limits := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
	w, err := journal.Open(journal.Options{FS: fs, Dir: dir, Synchronous: true}, journal.Identity{Run: "command-source", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}}})
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := ecdsa.PrivateKeyFromBytes(keyBytes)
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
	target := transport.WritePeer{Addr: ecdsa.Address(key), Session: transport.NewWriteSession()}
	target.Session.BindObservationRun("command-source")
	ref := &journal.SessionRef{Run: "command-source", Ordinal: target.Session.ObservationID()}
	w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: target.Addr, Event: "attached"}})
	w.Put(journal.Record{Body: &journal.SessionRec{Session: ref, Peer: target.Addr, Event: journal.SessionObserved, Active: true}})
	observer := commandWriteSource{writer: w, owner: transport.NewAttemptOwner()}
	options := limits.WriteOptions()
	options.Trace = observer
	ledger, err := transport.NewWriteLedger(options)
	if err != nil {
		t.Fatal(err)
	}
	code := uint64(m.Code)
	ticket, d := ledger.Prepare(target, code, raw)
	if d != transport.WriteReserved {
		t.Fatal(d)
	}
	attempt := transport.NewWriteSendAttempt(observer.owner, 1, ticket, "")
	source, ok := attempt.WriteSource()
	if !ok {
		t.Fatal("normal reservation source absent")
	}
	ledger.QueueResult(ticket, transport.Queued)
	if !ledger.Complete(ticket, transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(raw), Result: transport.LocalWriteOK}) {
		t.Fatal("normal metadata completion missing")
	}
	if differentRecordedCode {
		code++
	} // Offline metadata only; payload stays exact.
	w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 1, Session: ref, Code: code, Payload: raw, Write: transport.WriteOK, WriteAttempt: &journal.WriteAttemptSource{Sequence: attempt.Sequence, WriterRun: source.WriterRun, Ledger: source.Ledger, Request: source.Request}}})
	target.Session.Close()
	w.Put(journal.Record{Body: &journal.SessionRec{Session: ref, Peer: target.Addr, Event: string(transport.SessionRemoved)}})
	ledger.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckWriteIOCommandScopeLimitsAndContradiction(t *testing.T) {
	fs := fsys.NewMem()
	commandWriteIOFixture(t, fs, "/io-command", false)
	args := []string{"check-write-io", "--dir", "/io-command", "--max-records", "1000", "--max-ledgers", "4", "--max-reordered", "16", "--max-sessions", "8", "--max-requests", "16", "--max-frames", "16"}
	var check journal.WriteIOCheck
	runJSON(t, fs, 0, &check, args...)
	if check.Status != "consistent" || check.Writes != 1 || check.PhysicalStatus != "unavailable" || check.Unmeasured != 1 {
		t.Fatal("command overstated its scope", check)
	}
	runJSON(t, fs, 2, nil, "check-write-io", "--dir", "/io-command")
	limited := append([]string(nil), args...)
	limited[4] = "1"
	runJSON(t, fs, 69, &check, limited...)
	if check.Reason != "record_limit" {
		t.Fatal(check)
	}
	// Duplicate only offline metadata in an isolated in-memory directory to
	// prove collection stops at the source-frame budget before indexing it.
	records, err := journal.ReadAll(fs, "/io-command")
	if err != nil {
		t.Fatal(err)
	}
	var identity journal.Identity
	for _, record := range records {
		if s, ok := record.Body.(*journal.SegmentRec); ok {
			identity = s.Identity
			break
		}
	}
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/io-frame-budget", Synchronous: true}, identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if _, header := record.Body.(*journal.SegmentRec); header {
			continue
		}
		w.Put(record)
		if _, frame := record.Body.(*journal.MsgRec); frame {
			w.Put(record)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	limited = append([]string(nil), args...)
	limited[2] = "/io-frame-budget"
	limited[len(limited)-1] = "1"
	runJSON(t, fs, 69, &check, limited...)
	if check.Reason != "frame_limit" {
		t.Fatal("collection exceeded source-frame budget", check)
	}
	commandWriteIOFixture(t, fs, "/io-contradiction", true)
	args[2] = "/io-contradiction"
	runJSON(t, fs, 1, &check, args...)
	if check.Status != "inconsistent" || check.PhysicalStatus != "unavailable" {
		t.Fatal(check)
	}
	writeJournal(t, fs)
	args[2] = "/j"
	runJSON(t, fs, 69, &check, args...)
	if check.Status != "unavailable" {
		t.Fatal("legacy recording silently used as new source evidence", check)
	}
}
