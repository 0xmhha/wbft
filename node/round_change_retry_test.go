package node

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// A normal single-validator Node builds one block. This verifies the supported
// construction/handshake/header path, not multi-peer retry or physical writes.
func TestNodeRoundChangeRetryMatchingStartupAndRestartGuard(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	genesis.Header.Time = 999
	a := newTestApp(raw, genesis)
	fs := fsys.NewMem()
	policy := &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
	cfg := Config{DataDir: "/retry-node", RunID: "normal-retry-node", RoundChangeRetry: policy}
	deps := Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: fs, key: key, clock: cacheObservationClock{}}
	n, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	policy.MaxIntervalMs++ // Caller options are no longer owned by Node.
	a.cons = n.Consensus()
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.waitHead(t, 1, 5*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	if n.cfg.RoundChangeRetry.MaxIntervalMs != 8000 {
		t.Fatal("caller changed frozen policy")
	}
	found := false
	for _, option := range n.improvements() {
		if option.Name == "round_change_retry" && option.Source == "node" {
			found = true
		}
	}
	if !found {
		t.Fatal("run-scoped policy declaration missing")
	}
	records, err := journal.ReadAll(fs, "/retry-node/journal")
	if err != nil {
		t.Fatal(err)
	}
	headers := 0
	for _, record := range records {
		if segment, ok := record.Body.(*journal.SegmentRec); ok {
			headers++
			if segment.Core.RoundChangeRetry == nil || segment.Core.RoundChangeRetry.Profile != journal.RoundChangeRetryProfile || segment.Core.RoundChangeRetry.MaxIntervalMs != 8000 {
				t.Fatal("actual Node journal policy differs")
			}
		}
	}
	if headers == 0 {
		t.Fatal("no actual Node journal header")
	}
	wals, _, err := wal.ReadAll(fs, "/retry-node/wal")
	if err != nil {
		t.Fatal(err)
	}
	boundaries := 0
	for _, record := range wals {
		if record.Kind == 1 || record.Kind == 6 {
			boundaries++
			if record.Format != 4 {
				t.Fatal("Node omitted retry WAL profile")
			}
		}
	}
	if boundaries == 0 {
		t.Fatal("no actual Node boundary")
	}
	before := codec.BlockHash(a.Head())
	for _, maximum := range []uint64{0, 9000} {
		config := cfg
		config.RunID = "normal-retry-config-mismatch"
		config.RoundChangeRetry = nil
		if maximum != 0 {
			config.RoundChangeRetry = &consensus.RoundChangeRetryOptions{MaxIntervalMs: maximum}
		}
		next, err := New(config, deps)
		if err != nil {
			t.Fatal(err)
		}
		a.cons = next.Consensus()
		if err := next.Start(t.Context()); err == nil {
			_ = next.Stop()
			t.Fatal("mismatching restart profile accepted", maximum)
		}
		_ = next.Stop()
		if codec.BlockHash(a.Head()) != before {
			t.Fatal("application changed before profile refusal")
		}
	}
}
