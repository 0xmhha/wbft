package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft/codec"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func retryCommandLimits() journal.RetrySourceLimits {
	core := journal.CoreSourceLimits{Records: 1000, Runs: 8, Steps: 1000, Environments: 1000, Outputs: 1000, Bytes: 1 << 20}
	return journal.RetrySourceLimits{Timers: journal.TimerSourceLimits{Core: core, Operations: 1000, Bindings: 1000, Bytes: 1 << 20},
		Signer: privval.SourceLimits{Lifetimes: 8, Operations: 1000, Records: 1000, Bytes: 1 << 20}, Writes: journal.WriteCacheCheckLimits{Records: 1000, Ledgers: 8, Reordered: 32}}
}

func retryCommandHeader(t *testing.T, fs fsys.FS, run string, policy *journal.RoundChangeRetryOptions) {
	t.Helper()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/retry", Synchronous: true}, journal.Identity{Self: nodeA, Run: run, Core: journal.CoreOptions{RoundChangeRetry: policy}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRetrySourceCommandExplicitLimitsAndUnavailableEvidence(t *testing.T) {
	fs := fsys.NewMem()
	retryCommandHeader(t, fs, "normal-header", &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 8000})
	limits := retryCommandLimits()
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFileAtomic(fs, "/", "/limits.json", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var check journal.RetrySourceCheck
	runJSON(t, fs, 69, &check, "check-round-change-retry", "--dir", "/retry", "--source-limits", "/limits.json")
	if check.Status != "unavailable" || check.PhysicalStatus != "unavailable" {
		t.Fatal("header alone became proof", check)
	}
	runJSON(t, fs, 2, nil, "check-round-change-retry", "--dir", "/retry")
	for _, invalid := range [][]byte{[]byte(`{}`), []byte(`{"Unknown":1}`), append(raw, []byte(` {}`)...), bytes.Repeat([]byte{' '}, 65537)} {
		if err := fsys.WriteFileAtomic(fs, "/", "/invalid.json", invalid, 0o600); err != nil {
			t.Fatal(err)
		}
		runJSON(t, fs, 2, nil, "check-round-change-retry", "--dir", "/retry", "--source-limits", "/invalid.json")
	}
	// Two normally encoded declarations with the same writer identity and
	// different policy values are contradictory retained metadata, not a
	// live-node fault or a mutation of an existing WAL.
	retryCommandHeader(t, fs, "normal-header", &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 9000})
	runJSON(t, fs, 1, &check, "check-round-change-retry", "--dir", "/retry", "--source-limits", "/limits.json")
	if check.Status != "inconsistent" || check.Reason != "writer_retry_profile_changed" {
		t.Fatal("conflicting declarations became a usage error or success", check)
	}
}

func TestR01RetryProfileRefusalPrecedesAnyOutput(t *testing.T) {
	for _, profile := range []uint64{0, journal.RoundChangeRetryProfile, 77} {
		for _, timerTrace := range []uint64{0, journal.TimerTraceVersion} {
			t.Run(fmt.Sprintf("profile=%d/timer=%d", profile, timerTrace), func(t *testing.T) {
				fs := fsys.NewMem()
				core := journal.CoreOptions{CacheTrace: journal.CacheTraceVersion, TimerTrace: timerTrace}
				if profile != 0 {
					core.RoundChangeRetry = &journal.RoundChangeRetryOptions{Profile: profile, MaxIntervalMs: 8000}
				}
				w, err := journal.Open(journal.Options{FS: fs, Dir: "/new-mode", Synchronous: true, SegmentBytes: 350}, journal.Identity{Self: nodeA, Run: "new-mode", Core: core})
				if err != nil {
					t.Fatal(err)
				}
				input, err := inputlog.Encode(consensus.Start{})
				if err != nil {
					t.Fatal(err)
				}
				w.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart, Input: input, Via: "engine", HeadNumber: types.HeightFromUint64(1)}})
				if profile == 0 {
					w.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Sequence: 1, Action: "gossip", Code: uint64(codec.CodeRoundChange), Key: types.Hash{1}, PayloadSHA256: types.Hash{2}, Cause: event.CauseRetry, Available: true,
						Retry: transport.RoundChangeRetrySource{Version: 1, EngineRun: 1, Step: 2, Output: 3, Generation: 4, Height: "1", Round: "1", SigningKey: types.Hash{3}}}})
				}
				for request := uint64(1); request <= 8; request++ {
					w.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: request, Syncing: true}})
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				for _, from := range []string{"", "999999999"} {
					_, err := exportR01(fs, "/new-mode", "/out", from, "")
					if err == nil || !strings.Contains(err.Error(), "round-change retry") {
						t.Fatal("new mode silently projected as old R01", err)
					}
					if _, err := fs.ReadDir("/out"); !fsys.IsNotExist(err) {
						t.Fatal("unsupported export created partial output", err)
					}
				}
				if _, err := exportBundle(fs, "/new-mode", "/original.tar", "", "", 0); err != nil {
					t.Fatal("original bundle path rejected readable new mode", err)
				}
				bundle, err := fs.ReadFile("/original.tar")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := journal.ReadBundle(bytes.NewReader(bundle), fs, "/original"); err != nil {
					t.Fatal(err)
				}
				records, err := journal.ReadAll(fs, "/original")
				if err != nil || len(records) == 0 {
					t.Fatal("original bundle lost records", err)
				}
				declaration := records[0].Body.(*journal.SegmentRec).Core.RoundChangeRetry
				if profile == 0 && declaration != nil || profile != 0 && (declaration == nil || declaration.Profile != profile || declaration.MaxIntervalMs != 8000) {
					t.Fatal("bundle rewrote original profile", declaration)
				}
			})
		}
	}
}
