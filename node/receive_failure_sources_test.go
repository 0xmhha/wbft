package node

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type mutableFailureWriterRun struct {
	journal.Writer
	run string
}

func (w *mutableFailureWriterRun) CaptureRun() string { return w.run }

// The cache and signature checks are real local API operations. Queue and
// publication coordinates below are an explicit adapter model, not a running
// receiver, original core transcript, socket frame or crypto-failure proof.
func TestReceiveFailureRecorderFrozenWriterAndDistinctKinds(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		t.Run(fmt.Sprint(synchronous), func(t *testing.T) {
			fs := fsys.NewMem()
			config, _ := testGenesis(t, testKey(0))
			limits := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
			w, err := journal.Open(journal.Options{FS: fs, Dir: "/failure-recorder", Synchronous: synchronous}, journal.Identity{Run: "original-failure-writer", Core: journal.CoreOptions{
				ChainConfig:         config,
				CachePolicy:         &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits},
				ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2},
			}})
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					if err := w.Close(); err != nil {
						t.Error(err)
					}
				}
			})
			writer := &mutableFailureWriterRun{Writer: w, run: w.CaptureRun()}
			rec := newSessionFrameRecorder(writer, fixedClock{}, 0)
			writer.run = "later-caller-value"
			cache, err := transport.NewReceiveFailureCache(transport.ReceiveFailureOptions{Entries: 2, Trace: rec})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cache.Close)
			scope := transport.NewValidationScope()
			defer scope.Close()
			source := transport.ReceiveFailureSource{EngineRun: 1, SnapshotStep: 1, SnapshotPhase: transport.ReceiveFailureStart, SnapshotHash: types.Hash{9}}
			context := cache.BeginContext(scope, source)
			key, err := ecdsa.PrivateKeyFromBytes(testKey(0))
			if err != nil {
				t.Fatal(err)
			}
			message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(10)}, Digest: types.Hash{1}}
			signing, err := codec.SigningPayload(message, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			message.Signature, err = ecdsa.SignData(signing, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := codec.EncodeMessage(message)
			if err != nil {
				t.Fatal(err)
			}
			if v, phase, err := consensus.RecoverWithFailure(message.Code, raw, nil); err != nil || phase != consensus.RecoverySucceeded || v.Source != ecdsa.Address(key) {
				t.Fatal("owned signature did not recover normally", phase, err)
			}
			in := transport.Inbound{Peer: ecdsa.Address(key), Code: uint64(message.Code), Payload: raw}
			source.WorkerRequest = 1
			if _, ok := cache.Lookup(context, in, source); ok {
				t.Fatal("empty cache produced a failure hit")
			}
			if v, phase, err := consensus.RecoverWithFailure(message.Code, raw, func(types.Address, types.View) bool { return false }); err != ecdsa.ErrUnauthorizedAddress || phase != consensus.RecoveryMembership || v != nil {
				t.Fatal("local authority mismatch changed class", phase, err)
			}
			original, stored := cache.Record(context, in, transport.ReceiveMembershipFailure, source)
			if !stored || original.Run != "original-failure-writer" {
				t.Fatal("original writer namespace was relabeled", original)
			}
			source.WorkerRequest = 4
			hit, ok := cache.Lookup(context, in, source)
			if !ok || hit.Reference != original || hit.Lookup.Sequence <= original.Sequence || hit.Source.WorkerRequest != 1 {
				t.Fatal("lookup lost the original failure", hit)
			}
			hitSource := journal.InboxFailureHitRec{Version: journal.ReceiveFailureRecordVersion, Lookup: hit.Lookup, Original: hit.Reference, Class: hit.Class, Source: journal.InboxRec{
				Version: journal.InboxSourceVersion, Action: "failure_hit", Result: "membership", Sequence: 6, Request: 4, Peer: in.Peer, Code: in.Code,
				SnapshotEngine: 1, SnapshotStep: 1, SnapshotPhase: "start", SnapshotContextHash: source.SnapshotHash,
				Order: []types.Address{in.Peer}, Mono: uint64((fixedClock{}).Mono()), WallNs: uint64((fixedClock{}).Now().UnixNano()),
			}}
			rec.ObserveInboxFailureHit(hitSource)
			// Only detached metadata changes after observation; no input or signature
			// bytes are modified or delivered to any receiver.
			hitSource.Source.Order[0] = types.Address{99}
			cache.Close()
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			rows, err := journal.ReadAll(fs, "/failure-recorder")
			if err != nil {
				t.Fatal(err)
			}
			operations, consumed := 0, 0
			for _, row := range rows {
				switch body := row.Body.(type) {
				case *journal.GapRec:
					t.Fatal("adapter dropped diagnostic evidence", body)
				case *journal.ReceiveFailureCacheRec:
					operations++
					if row.Kind != journal.KindReceiveFailure || body.Transition.Run != original.Run || body.Transition.Sequence != uint64(operations) || body.Mono != (fixedClock{}).Mono() || body.WallNs != (fixedClock{}).Now().UnixNano() {
						t.Fatal("cache order, namespace or callback time changed", body)
					}
					if body.Transition.Action == "lookup" && body.Transition.Hit && (body.Transition.Reference != original || body.Transition.Original.WorkerRequest != 1 || body.Transition.Source.WorkerRequest != 4) {
						t.Fatal("current lookup replaced original failure source", body)
					}
				case *journal.InboxFailureHitRec:
					consumed++
					if row.Kind != journal.KindInboxFailureHit || body.Lookup != hit.Lookup || body.Original != original || body.Source.Action != "failure_hit" || body.Source.Order[0] != in.Peer || len(body.Source.Payload) != 0 || body.Source.Signer != (types.Address{}) {
						t.Fatal("separate hit borrowed caller metadata or became a check", body)
					}
				case *journal.InboxRec, *journal.SignerCallRec, *journal.ReceiveCacheRec:
					t.Fatal("failure observation fabricated another operation", body)
				}
			}
			if operations != 5 || consumed != 1 {
				t.Fatal("actual cache callback or distinct hit was lost", operations, consumed)
			}
			checked, err := journal.CheckReceiveFailureSources(rows, journal.ReceiveFailureLimits{Caches: 4, Inbox: journal.InboxLimits{
				Core: journal.CoreSourceLimits{Records: 1000, Runs: 4, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 4 << 20}, Operations: 1000, Entries: 100, Peers: 10, Frames: 100, Bytes: 4 << 20,
			}})
			if err != nil || checked.Status != "unavailable" || checked.VerifiedFailures != 0 || checked.ConsumedFailures != 0 {
				t.Fatal("adapter model was promoted without original core/frame inputs", checked, err)
			}
			t.Logf("original_writer=%s cache_operations=%d separate_hits=%d original_source_status=%s reason=%s crypto_failure_hit=false", original.Run, operations, consumed, checked.Status, checked.Reason)
		})
	}
}
