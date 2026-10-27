package journal

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestNormalRetryHeaderAndFrozenDeclaration(t *testing.T) {
	id := ident()
	id.Core = CoreOptions{Self: id.Self, ChainConfig: []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"proposerPolicy":0}}}`),
		Improvements: uint64(consensus.RestartSafety), ProposerPolicyProfile: CheckedProposerPolicyProfile,
		RoundChangeRetry: &RoundChangeRetryOptions{Profile: RoundChangeRetryProfile, MaxIntervalMs: 8000}}
	cfg, err := id.Core.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	actual := consensus.Options{Config: cfg, Self: id.Self, Improvements: consensus.RestartSafety, RoundChangeRetry: &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}}
	if err := id.Core.ValidateCoreDeclaration(actual); err != nil {
		t.Fatal(err)
	}
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/retry-header", Synchronous: true, SegmentBytes: 400}, id)
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary caller-owned options and returned copies cannot change later
	// rotation headers. No live source, WAL or packet is modified by this test.
	id.Core.RoundChangeRetry.MaxIntervalMs++
	id.Core.ChainConfig[0] = ' '
	copy := w.CoreDeclaration()
	copy.RoundChangeRetry.MaxIntervalMs++
	copy.ChainConfig[0] = ' '
	if err := w.CoreDeclaration().ValidateCoreDeclaration(actual); err != nil {
		t.Fatal("frozen declaration changed", err)
	}
	for request := uint64(1); request <= 8; request++ {
		w.Put(Record{Body: &SyncRec{Stage: "requested", Request: request, Syncing: true, Mono: time.Duration(request)}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/retry-header")
	if err != nil {
		t.Fatal(err)
	}
	segments := 0
	for _, record := range records {
		if segment, ok := record.Body.(*SegmentRec); ok {
			segments++
			if err := segment.Core.ValidateCoreDeclaration(actual); err != nil {
				t.Fatal("rotation declaration differs", err)
			}
			if _, err := segment.Core.Configuration(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if segments < 2 {
		t.Fatal("normal rotation not exercised")
	}
}

type normalRetryJournalTransport struct {
	target transport.WritePeer
	writes int
}

func (tr *normalRetryJournalTransport) Send([]types.Address, uint64, []byte) []transport.SendResult {
	return nil
}
func (tr *normalRetryJournalTransport) SetReceiver(transport.Receiver)         {}
func (tr *normalRetryJournalTransport) PeerEvents() <-chan transport.PeerEvent { return nil }
func (tr *normalRetryJournalTransport) Disconnect(types.Address, string)       {}
func (tr *normalRetryJournalTransport) Peers() []transport.PeerInfo {
	return []transport.PeerInfo{{Addr: tr.target.Addr}}
}
func (tr *normalRetryJournalTransport) WritePeers() []transport.WritePeer {
	return []transport.WritePeer{tr.target}
}
func (tr *normalRetryJournalTransport) SendWrite(target transport.WritePeer, code uint64, payload []byte, _ transport.SendAttempt, done func(transport.WriteReceipt)) transport.SendResult {
	tr.writes++
	done(transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(payload), Result: transport.LocalWriteOK})
	return transport.Queued
}

func TestNormalRetryWriteRecordAndIndependentModel(t *testing.T) {
	m := deferredNormalMessage(t)
	message, err := codec.DecodeMessage(m.Code, m.Payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := codec.SigningPayload(message, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := ident()
	id.Self, id.Core.Self = m.Peer, m.Peer
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}
	id.Core.RoundChangeRetry = &RoundChangeRetryOptions{Profile: RoundChangeRetryProfile, MaxIntervalMs: 8000}
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/retry-write", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	trace := &journalWriteTransitions{writer: w, start: time.Now()}
	tr := &normalRetryJournalTransport{target: transport.WritePeer{Addr: types.Address{7}, Session: transport.NewWriteSession()}}
	options := id.Core.CachePolicy.Limits.WriteOptions()
	options.Trace = trace
	d, err := transport.NewDedup(tr, transport.DedupOptions{Self: m.Peer, RoundChangeRetry: true, KeyWithCode: true, RecordAfterSend: true, CompletedWrites: &options})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := validator.NewSet([]types.Address{m.Peer, tr.target.Addr}, make([][]byte, 2), types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	d.Broadcast(vs, uint64(m.Code), m.Payload, event.CauseBroadcast)
	if p := d.GossipTargets(vs, uint64(m.Code), m.Payload, event.CauseRetry); len(p.Suppressed) != 1 {
		t.Fatal("ordinary cause escaped recent cache")
	}
	request := transport.RoundChangeRetryRequest{View: message.View, Generation: 2, SigningKey: codec.DedupKey(body), PreviousPayload: m.Payload,
		Source: transport.RoundChangeRetrySource{EngineRun: 1, Step: 2, Output: 3}}
	if p := d.RetryOwnRoundChange(vs, m.Payload, request); len(p.Targets) != 1 || tr.writes != 2 {
		t.Fatal("actual retry reservation missing", p)
	}
	d.CloseCompletedWrites()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/retry-write")
	if err != nil {
		t.Fatal(err)
	}
	check, err := CheckWriteCacheTransitions(records, WriteCacheCheckLimits{Records: 1000, Ledgers: 4, Reordered: 16})
	if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" {
		t.Fatal("independent reservation model differs", check, err)
	}
	retries := 0
	for _, record := range records {
		if r, ok := record.Body.(*WriteCacheRec); ok && r.Transition.Retry.Version != 0 {
			retries++
			raw, err := encodeBody(record, record.JSeq)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeBody(KindWriteCache, raw)
			if err != nil || !reflect.DeepEqual(r.Transition, decoded.Body.(*WriteCacheRec).Transition) {
				t.Fatal("separate retry source changed", err)
			}
			if size(record) <= size(Record{Body: &WriteCacheRec{Transition: transport.WriteTransition{}}}) {
				t.Fatal("retry source omitted from bounds")
			}
		}
	}
	if retries != 1 {
		t.Fatal("retry source count", retries)
	}
	if _, err := id.Core.Configuration(); err != ErrCachePolicyReplay {
		t.Fatal("retry declaration enabled unsupported functional cache replay", err)
	}
}

func TestNormalRetrySourcePreservesOldBytes(t *testing.T) {
	r := &CacheRec{Instance: 1, Sequence: 2, Action: "gossip", Code: uint64(codec.CodeRoundChange), Key: types.Hash{1}, PayloadSHA256: types.Hash{2}, Cause: event.CauseRetry, Available: true, Candidates: []types.Address{{7}}, Targets: []types.Address{{7}}}
	before, err := rlp.Encode([]any{uint64(Format), uint64(3), r.Instance, r.Sequence, r.Action, r.Self, r.Peer, r.PeerCapacity, r.MessageCapacity, r.Code, r.Key, r.PayloadSHA256, string(r.Cause), uint64(0), uint64(0), uint64(1), r.Candidates, r.Targets, []types.Address{}, uint64(0), uint64(0)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeCacheRec(r, 3)
	if err != nil || !bytes.Equal(raw, before) {
		t.Fatal("absent retry changed original cache bytes", err)
	}
	r.Retry = transport.RoundChangeRetrySource{Version: 1, EngineRun: 1, Step: 2, Output: 3, Generation: 4, Height: "11", Round: "1", SigningKey: types.Hash{9}}
	raw, err = encodeCacheRec(r, 3)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCacheRec(raw)
	if err != nil || decoded.Body.(*CacheRec).Retry != r.Retry {
		t.Fatal("retry source did not round-trip", err)
	}
	source := minimalCoreSource(t)
	source.RetryMaximumMs = 8000
	raw, err = encodeCoreStepRec(source, 4)
	if err != nil {
		t.Fatal(err)
	}
	step, err := decodeCoreStepRec(raw)
	if err != nil || step.Body.(*CoreStepRec).RetryMaximumMs != 8000 {
		t.Fatal("actual policy observation lost", err)
	}
}
