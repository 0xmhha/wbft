package node

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type mutableFailureDeclaration struct {
	*journal.FileWriter
	core journal.CoreOptions
}

func (w *mutableFailureDeclaration) CoreDeclaration() journal.CoreOptions { return w.core }

func TestNodeReceiveFailureDiagnosticDeclarationAndRecorderCopy(t *testing.T) {
	limits := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
	config, _ := testGenesis(t, testKey(0))
	for _, mode := range []string{"matched", "capacity", "write_limits", "no_declaration", "unknown_profile", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			mem := fsys.NewMem()
			core := journal.CoreOptions{ChainConfig: config, CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2}}
			cfg := Config{RunID: "failure-node-declaration", CachePolicy: &limits, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}, Journal: JournalConfig{Disabled: true}}
			switch mode {
			case "capacity":
				core.ReceiveFailureCache.Entries++
			case "write_limits":
				core.CachePolicy.Limits.WritePending++
			case "no_declaration":
				core.ReceiveFailureCache = nil
			case "unknown_profile":
				core.ReceiveFailureCache.Profile = 77
			case "disabled":
				cfg.ReceiveFailureCache = nil
			}
			w, err := journal.Open(journal.Options{FS: mem, Dir: "/declaration", Synchronous: true}, journal.Identity{Run: cfg.RunID, Core: core})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := w.Close(); err != nil {
					t.Error(err)
				}
			}()
			deps := Deps{Transport: &diagnosticIsolatedTransport{}, Diagnostics: &DiagnosticOptions{Writer: w, WALRead: wal.ReadSourceLimits{Frames: 100, Bytes: 1 << 20}, SignerRecords: 100, SignerBytes: 1 << 20, ApplicationBytes: 1 << 20}}
			err = freezeDiagnostics(cfg, &deps)
			if (err == nil) != (mode == "matched") {
				t.Fatal("node declaration/runtime equality gate changed", mode, err)
			}
			if mode != "matched" {
				return
			}
			caller := &mutableFailureDeclaration{FileWriter: w, core: w.CoreDeclaration()}
			rec := newSessionFrameRecorder(caller, fixedClock{}, 0)
			caller.core.ReceiveFailureCache.Entries = 9
			caller.core.CachePolicy.Limits.WritePending = 99
			caller.core.ChainConfig[0] = ' '
			frozen := rec.CoreDeclaration()
			if frozen.ReceiveFailureCache.Entries != 2 || frozen.CachePolicy.Limits != limits || !bytes.Equal(frozen.ChainConfig, config) {
				t.Fatal("recorder borrowed a mutable declaration")
			}
			frozen.ReceiveFailureCache.Entries = 7
			frozen.CachePolicy.Limits.ReceivePending = 99
			frozen.ChainConfig[0] = ' '
			if rec.CoreDeclaration().ReceiveFailureCache.Entries != 2 || rec.CoreDeclaration().CachePolicy.Limits != limits || !bytes.Equal(rec.CoreDeclaration().ChainConfig, config) {
				t.Fatal("a returned declaration changed the frozen recorder")
			}
		})
	}
}

// Actual Node/core/app/signing sources run twice over the same owned state.
// No peer or received frame is attached, so this is not a failure-hit or socket
// source proof and does not establish full source consistency or replay.
func TestNodeReceiveFailureDiagnosticsNormalColdAndStored(t *testing.T) {
	key := testKey(0)
	config, genesis := testGenesis(t, key)
	parsed, err := types.ParseChainConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestApp(config, genesis)
	mem := fsys.NewMem()
	limits := transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}
	for lifetime := 0; lifetime < 2; lifetime++ {
		run := fmt.Sprintf("failure-node-%d", lifetime)
		dir := "/" + run
		w, err := journal.Open(journal.Options{FS: mem, Dir: dir, Synchronous: true}, journal.Identity{Run: run, Core: journal.CoreOptions{
			ChainConfig: config, Self: parsed.Init.Validators[0], ProposerPolicyProfile: journal.CheckedProposerPolicyProfile, Improvements: uint64(consensus.RestartSafety), TimerTrace: journal.TimerTraceVersion,
			CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2},
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
		cfg := Config{DataDir: "/data", RunID: run, CachePolicy: &limits, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}, Journal: JournalConfig{Disabled: true}}
		n, err := New(cfg, Deps{App: a, Authority: a, fs: mem, key: key, Transport: &diagnosticIsolatedTransport{}, Diagnostics: &DiagnosticOptions{
			Writer: w, WALRead: wal.ReadSourceLimits{Frames: 4096, Bytes: 8 << 20}, SignerRecords: 4096, SignerBytes: 8 << 20, ApplicationBytes: 8 << 20, WALReadOnStop: true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(t, n) })
		a.cons = n.Consensus()
		target := a.Head().Number.RefLow64() + 1 //wbft:low64 HH-60
		if err := n.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.waitHead(t, target, 20*time.Second)
		if err := n.Stop(); err != nil {
			t.Fatal(err)
		}
		if n.journal != nil {
			t.Fatal("diagnostics enabled a functional journal")
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		closed = true
		rows, err := journal.ReadAll(mem, dir)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[journal.Kind]int{}
		context, cacheClosed := false, false
		for _, row := range rows {
			counts[row.Kind]++
			switch s := row.Body.(type) {
			case *journal.GapRec:
				t.Fatal("actual node evidence was dropped", s)
			case *journal.SegmentRec:
				if s.Core.ReceiveFailureCache == nil || s.Core.ReceiveFailureCache.Entries != 2 {
					t.Fatal("writer lost its declared entry bound")
				}
			case *journal.ReceiveFailureCacheRec:
				if s.Transition.Run != run || s.Transition.Capacity != 2 || s.Transition.Unavailable != "" {
					t.Fatal("actual node cache source lost namespace or limit", s)
				}
				context = context || s.Transition.Action == "context"
				cacheClosed = cacheClosed || s.Transition.Action == "close"
			}
		}
		if !context || !cacheClosed {
			t.Fatal("actual node lifetime did not reach failure cache", context, cacheClosed)
		}
		for _, kind := range []journal.Kind{journal.KindCoreStep, journal.KindInbox, journal.KindReceiveCache, journal.KindSignerCall, journal.KindWALRead} {
			if counts[kind] == 0 {
				t.Fatal("node coordinator lost original source", kind, counts)
			}
		}
		if counts[journal.KindInboxFailureHit] != 0 {
			t.Fatal("no-peer node fabricated a received failure hit")
		}
		t.Logf("normal_failure_node lifetime=%d cache_events=%d original_core_steps=%d signer_calls=%d physical_status=unavailable", lifetime, counts[journal.KindReceiveFailure], counts[journal.KindCoreStep], counts[journal.KindSignerCall])
	}
}
