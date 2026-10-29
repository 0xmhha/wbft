package node

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestValidatorStartNodeFrozenHistoryAndOrdinaryReopen(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	genesis.Header.Time = 999
	a := newTestApp(raw, genesis)
	fs := fsys.NewMem()
	limits := &runner.ValidatorHistoryLimits{Bytes: 1 << 20, Records: 4096}
	cfg := Config{DataDir: "/validator-history-node", RunID: "history-normal-first", Improvements: []string{"defer_validator_start"}, ValidatorHistory: limits}
	deps := Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: fs, key: key, clock: cacheObservationClock{}}
	n, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	limits.Records++
	if n.cfg.ValidatorHistory.Records != 4096 {
		t.Fatal("caller changed frozen history")
	}
	a.cons = n.Consensus()
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.waitHead(t, 1, 5*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	records, _, err := wal.ReadAll(fs, "/validator-history-node/wal")
	if err != nil || len(records) == 0 || records[0].Format != 5 || records[0].Kind != 1 {
		t.Fatal("Node omitted selected seed", err)
	}
	config := n.cfg
	config.RunID = "history-normal-second"
	next, err := New(config, deps)
	if err != nil {
		t.Fatal(err)
	}
	a.cons = next.Consensus()
	if err := next.Start(t.Context()); err != nil {
		t.Fatal("same profile ordinary reopen failed", err)
	}
	if err := next.Stop(); err != nil {
		t.Fatal(err)
	}
	bad := config
	bad.Improvements = nil
	if _, err := New(bad, deps); err == nil {
		t.Fatal("history configured without explicit selection")
	}
}
