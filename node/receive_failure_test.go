package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event/schema"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestNodeReceiveFailureConfigurationAndStagedDiagnostics(t *testing.T) {
	limits := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
	for _, test := range []struct {
		name string
		cfg  Config
	}{
		{"zero", Config{CachePolicy: &limits, Journal: JournalConfig{Disabled: true}, ReceiveFailureCache: &ReceiveFailureCacheConfig{}}},
		{"limit", Config{CachePolicy: &limits, Journal: JournalConfig{Disabled: true}, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: transport.InmemoryMessages + 1}}},
		{"policy", Config{Journal: JournalConfig{Disabled: true}, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}}},
		{"functional_journal", Config{CachePolicy: &limits, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if n, err := New(test.cfg, Deps{}); n != nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "receive failure") {
				t.Fatal("invalid ordinary option combination accepted", n, err)
			}
		})
	}
	defaults, err := json.Marshal(Config{})
	if err != nil || bytes.Contains(defaults, []byte("ReceiveFailureCache")) {
		t.Fatal("nil option changed default JSON", err)
	}
	options := &ReceiveFailureCacheConfig{Entries: 2}
	cfg := Config{ReceiveFailureCache: options, CachePolicy: &limits, Journal: JournalConfig{Disabled: true}}
	if err := freezeReceiveFailureCache(&cfg); err != nil {
		t.Fatal(err)
	}
	options.Entries = 3
	if cfg.ReceiveFailureCache.Entries != 2 {
		t.Fatal("caller changed the frozen node entry bound")
	}
	if err := freezeDiagnostics(cfg, &Deps{Diagnostics: &DiagnosticOptions{}}); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "receive failure cache diagnostic profile") {
		t.Fatal("node silently enabled an unsupported diagnostic combination", err)
	}
	mem := fsys.NewMem()
	w, err := journal.Open(journal.Options{FS: mem, Dir: "/failure-declaration", Synchronous: true}, journal.Identity{Run: "failure-declaration", Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()
	cfg.ReceiveFailureCache, cfg.RunID = nil, "failure-declaration"
	if err := freezeDiagnostics(cfg, &Deps{Diagnostics: &DiagnosticOptions{Writer: w}}); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "receive failure declaration") {
		t.Fatal("a decoded declaration invented an enabled node profile", err)
	}
}

// This pair uses actual Node/core/app/signing paths with no attached peers.
// It compares canonical signed blocks, private signing state and own WAL bytes;
// it does not claim socket I/O or a supported failure diagnostic profile.
func TestNodeReceiveFailurePreservesNormalSignedBlockAndWAL(t *testing.T) {
	var previousBlock, previousState []byte
	var previousOwn [][]byte
	for _, enabled := range []bool{false, true} {
		key := testKey(0)
		chainConfig, genesis := testGenesis(t, key)
		genesis.Header.Time = 999
		a := newTestApp(chainConfig, genesis)
		mem := fsys.NewMem()
		limits := transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}
		config := Config{DataDir: "/data", RunID: "failure-parity", CachePolicy: &limits, Journal: JournalConfig{Disabled: true}}
		if enabled {
			config.ReceiveFailureCache = &ReceiveFailureCacheConfig{Entries: 2}
		}
		var events bytes.Buffer
		n, err := New(config, Deps{App: a, Authority: a, Transport: &diagnosticIsolatedTransport{}, fs: mem, key: key, clock: cacheObservationClock{}, Events: &events})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(t, n) })
		if enabled {
			config.ReceiveFailureCache.Entries = 7
		}
		a.cons = n.Consensus()
		if err = n.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.waitHead(t, 1, 5*time.Second)
		if err = n.Stop(); err != nil {
			t.Fatal(err)
		}
		if a.Head().Number.CmpUint64(1) != 0 || n.journal != nil {
			t.Fatal("bounded target or disabled functional journal changed")
		}
		a.mu.Lock()
		block := a.byNum[1]
		a.mu.Unlock()
		encoded, err := codec.EncodeBlock(block)
		if err != nil {
			t.Fatal(err)
		}
		state, err := mem.ReadFile("/data/privval/state")
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := wal.ReadAll(mem, "/data/wal")
		if err != nil {
			t.Fatal(err)
		}
		var own [][]byte
		for _, row := range rows {
			if row.Format == 1 && row.Kind == 4 {
				own = append(own, row.Body)
			}
		}
		if len(own) != 3 {
			t.Fatal("normal signed own-message count changed", len(own))
		}
		if !enabled {
			previousBlock, previousState, previousOwn = encoded, state, own
		} else {
			if !bytes.Equal(encoded, previousBlock) || !bytes.Equal(state, previousState) || len(own) != len(previousOwn) {
				t.Fatal("failure cache changed normal signed block or signing state")
			}
			for i := range own {
				if !bytes.Equal(own[i], previousOwn[i]) {
					t.Fatal("failure cache changed normal signed WAL bytes")
				}
			}
		}
		starts := 0
		check, err := schema.Load()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(events.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			if err := check.Validate(line); err != nil {
				t.Fatal("actual node emitted an invalid public event", err)
			}
			var row struct {
				Kind   string `json:"kind"`
				Policy *struct {
					Profile string `json:"profile"`
					Entries uint64 `json:"entries"`
					Active  bool   `json:"active"`
				} `json:"receive_failure_cache"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				t.Fatal(err)
			}
			if row.Kind == "NODE_START" {
				starts++
				if !enabled && row.Policy != nil || enabled && (row.Policy == nil || row.Policy.Profile != transport.ReceiveFailureProfile || row.Policy.Entries != 2 || !row.Policy.Active) {
					t.Fatal("actual node start lost its frozen functional option")
				}
			}
		}
		if starts != 1 {
			t.Fatal("normal node lifetime declaration missing", starts)
		}
		found := false
		for _, family := range n.Metrics().Gather() {
			if family.Name == "wbft_cache_receive_failure_limit" {
				found = true
				if len(family.Samples) != 1 || family.Samples[0].Value != 2 {
					t.Fatal("functional option's configured metric changed")
				}
			}
		}
		if found != enabled {
			t.Fatal("default off gained a failure cache metric")
		}
		t.Logf("normal_failure_cache_node enabled=%t baseline_comparison_complete=%t own_records=%d diagnostic_profile_supported=false", enabled, enabled, len(own))
	}
}

// This adapter test invokes detached counting hooks, not a receiver or signer.
// Actual membership-worker reuse is covered separately in runner tests.
func TestNodeReceiveFailureMetricsSeparateRecoveryAndReuse(t *testing.T) {
	n := &Node{cfg: Config{ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}}, metrics: metrics.NewRegistry()}
	var config runner.Config
	var deps runner.Deps
	n.connectReceiveFailures(&config, &deps)
	if config.ReceiveFailureCache == nil || config.ReceiveFailureCache.Entries != 2 || config.ReceiveFailureCache.Trace != nil {
		t.Fatal("node failed to pass its explicit functional option")
	}
	for _, phase := range []consensus.RecoveryFailure{consensus.RecoverySucceeded, consensus.RecoveryDecode, consensus.RecoveryEncoding, consensus.RecoverySignature, consensus.RecoveryMembership} {
		deps.ReceiveRecoveryChecked(codec.CodePrepare, phase)
	}
	deps.ReceiveFailureHit(uint64(codec.CodePrepare), transport.ReceiveMembershipFailure)
	checks, hits := float64(0), float64(0)
	for _, family := range n.Metrics().Gather() {
		for _, sample := range family.Samples {
			if family.Name == "wbft_cache_receive_recovery_total" {
				checks += sample.Value
			}
			if family.Name == "wbft_cache_receive_failure_hits_total" {
				hits += sample.Value
				if sample.Labels["class"] != "membership" {
					t.Fatal("reuse changed its failed phase")
				}
			}
		}
	}
	if checks != 5 || hits != 1 || receiveFailureMetricCode(^uint64(0)) != "other" {
		t.Fatal("a reused failure became a new actual recovery or unbounded code label", checks, hits)
	}
}
