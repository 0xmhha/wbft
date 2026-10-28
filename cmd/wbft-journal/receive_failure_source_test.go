package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func failureCommandLimits() journal.ReceiveFailureLimits {
	return journal.ReceiveFailureLimits{Caches: 8, Inbox: journal.InboxLimits{
		Core:       journal.CoreSourceLimits{Records: 1000, Runs: 8, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20},
		Operations: 1000, Entries: 100, Peers: 10, Frames: 100, Bytes: 1 << 20,
	}}
}

func failureCommandHeader(t *testing.T, fs fsys.FS, entries uint64) {
	t.Helper()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/failure", Synchronous: true}, journal.Identity{Run: "failure-command", Core: journal.CoreOptions{
		CachePolicy:         &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}},
		ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: entries},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// These are newly written local diagnostic declarations, not mutated node data
// or a network fault. A declaration never supplies missing verification inputs.
func TestReceiveFailureSourceCommandLimitsAndDistinctOutcomes(t *testing.T) {
	fs := fsys.NewMem()
	failureCommandHeader(t, fs, 2)
	limits := failureCommandLimits()
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFileAtomic(fs, "/", "/limits.json", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var check journal.ReceiveFailureCheck
	args := []string{"check-receive-failures", "--dir", "/failure", "--source-limits", "/limits.json"}
	runJSON(t, fs, 69, &check, args...)
	if check.Status != "unavailable" || check.PhysicalStatus != "unavailable" || check.VerifiedFailures != 0 || check.ConsumedFailures != 0 || check.Inbox.Checked != 0 {
		t.Fatal("declaration became an executed verification", check)
	}
	runJSON(t, fs, 2, nil, "check-receive-failures", "--dir", "/failure")
	zeroFrames := failureCommandLimits()
	zeroFrames.Inbox.Frames = 0
	zeroRaw, err := json.Marshal(zeroFrames)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{[]byte(`{}`), []byte(`null`), []byte(`{"Unknown":1}`), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Repeat([]byte{' '}, 65537), zeroRaw} {
		if err := fsys.WriteFileAtomic(fs, "/", "/invalid.json", invalid, 0o600); err != nil {
			t.Fatal(err)
		}
		runJSON(t, fs, 2, nil, "check-receive-failures", "--dir", "/failure", "--source-limits", "/invalid.json")
	}
	// A second genuine writer with the same run and a different retained-entry
	// declaration is a metadata contradiction, never a fresh signer failure.
	failureCommandHeader(t, fs, 3)
	runJSON(t, fs, 1, &check, args...)
	if check.Status != "inconsistent" || check.Reason != "writer_failure_declaration_changed" {
		t.Fatal("declaration conflict lost its distinct result", check)
	}
	limits.Inbox.Core.Records = 1
	raw, err = json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFileAtomic(fs, "/", "/limits.json", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 69, &check, args...)
	if check.Reason != "record_limit" || check.VerifiedFailures != 0 {
		t.Fatal("limited prefix was mistaken for complete verification", check)
	}
}

func TestR01ReceiveFailureRefusalBeforeOutputAndBundlePreservation(t *testing.T) {
	// These fixtures contain explicit model coordinates and no original core
	// source or received frame. No consistent-source or runtime claim is made.
	for _, mode := range []string{"declaration", "unknown-declaration", "cache-body", "hit-body"} {
		t.Run(mode, func(t *testing.T) {
			fs := fsys.NewMem()
			core := journal.CoreOptions{}
			if mode == "declaration" || mode == "unknown-declaration" {
				profile := journal.ReceiveFailureCacheProfile
				if mode == "unknown-declaration" {
					profile = 77
				}
				core.CachePolicy = &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}
				core.ReceiveFailureCache = &journal.ReceiveFailureCacheOptions{Profile: profile, Entries: 2}
			}
			w, err := journal.Open(journal.Options{FS: fs, Dir: "/new-failure", Synchronous: true, SegmentBytes: 350}, journal.Identity{Run: "original-failure", Core: core})
			if err != nil {
				t.Fatal(err)
			}
			input, err := inputlog.Encode(consensus.Start{})
			if err != nil {
				t.Fatal(err)
			}
			w.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart, Input: input, Via: "engine", HeadNumber: types.HeightFromUint64(1)}})
			switch mode {
			case "cache-body":
				w.Put(journal.Record{Body: &journal.ReceiveFailureCacheRec{Version: journal.ReceiveFailureRecordVersion, Transition: transport.ReceiveFailureEvent{
					Run: "original-failure", Cache: 1, Sequence: 1, Action: "invalidate", Capacity: 2,
				}}})
			case "hit-body":
				w.Put(journal.Record{Body: &journal.InboxFailureHitRec{Version: journal.ReceiveFailureRecordVersion, Class: transport.ReceiveMembershipFailure, Unavailable: "failure_reference_unavailable", Source: journal.InboxRec{
					Version: journal.InboxSourceVersion, Action: "failure_hit", Result: "membership", Sequence: 2, Request: 1, SnapshotEngine: 1, SnapshotStep: 1, SnapshotPhase: "start", SnapshotContextHash: types.Hash{9},
				}}})
			}
			for request := uint64(1); request <= 8; request++ {
				w.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: request, Syncing: true}})
			}
			// The original bundle selects segments between height-bearing
			// steps. Bracket all model records so this comparison includes
			// the full fixture instead of an unrelated unindexed suffix.
			w.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 2, InputKind: inputlog.KindStart, Input: input, Via: "engine", HeadNumber: types.HeightFromUint64(1)}})
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			original, err := journal.ReadAll(fs, "/new-failure")
			if err != nil {
				t.Fatal(err)
			}
			for _, from := range []string{"", "999999999"} {
				if _, err := exportR01(fs, "/new-failure", "/out", from, ""); err == nil || !strings.Contains(err.Error(), "receive failure sources") {
					t.Fatal("new profile became an old R01 projection", err)
				}
				if _, err := fs.ReadDir("/out"); !fsys.IsNotExist(err) {
					t.Fatal("unsupported mode created partial output", err)
				}
			}
			if _, err := exportBundle(fs, "/new-failure", "/original.tar", "", "", 0); err != nil {
				t.Fatal(err)
			}
			bundle, err := fs.ReadFile("/original.tar")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.ReadBundle(bytes.NewReader(bundle), fs, "/retained"); err != nil {
				t.Fatal(err)
			}
			restored, err := journal.ReadAll(fs, "/retained")
			if err != nil || len(restored) != len(original) {
				t.Fatal("original bundle lost records", len(original), len(restored), err)
			}
			for i := range original {
				a, err := json.Marshal(original[i])
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(restored[i])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a, b) {
					t.Fatalf("original record %d was rewritten", i)
				}
			}
		})
	}
}
