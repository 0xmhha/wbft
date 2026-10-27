package runner

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// The future sender joins through a normal adopted validator rotation. No
// semantic mutations or network faults are injected into this local adapter.
func TestBindPriorHeadRetainsPendingAcrossRotation(t *testing.T) {
	k := newKeys(t, 5)
	old := nextHeightSet(t, k, []int{0, 1, 2, 3})
	next := nextHeightSet(t, k, []int{1, 2, 3, 4})
	seal := func(b *types.Block) *types.Block {
		var ps, cs []types.SealEntry
		for i := 0; i < 3; i++ {
			ps = append(ps, types.SealEntry{Sealer: uint32(i), Seal: k.bls[i].Sign(codec.SealData(b.Header, 0, types.PrepareSeal)).Bytes()})
			cs = append(cs, types.SealEntry{Sealer: uint32(i), Seal: k.bls[i].Sign(codec.SealData(b.Header, 0, types.CommitSeal)).Bytes()})
		}
		b, err := header.CommitHeader(b, types.Round{}, ps, cs)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	parent := block(t, 8, 0, k.addrs[3], types.Hash{7})
	h9 := seal(block(t, 9, 0, k.addrs[3], codec.BlockHash(parent.Header)))
	h10 := seal(block(t, 10, 1, k.addrs[3], codec.BlockHash(h9.Header)))
	b := block(t, 11, 2, k.addrs[4], codec.BlockHash(h10.Header))
	clock := &manualClock{}
	chain := &historicalChain{fakeChain: &fakeChain{head: h9.Header, vs: old, clock: clock, future: map[types.Hash]time.Duration{}, bad: map[types.Hash]bool{}}, past: old}
	fs := fsys.NewMem()
	policy := uint64(0)
	cfg := Config{Core: consensus.Options{Config: types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil), Improvements: consensus.ImprovementSet(0).With(consensus.BindPriorHead)}, ReplayWAL: true, Manual: true, NextHeight: &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}}
	var r *Runner
	var log *wal.Log
	var events *eventLog
	closeRunner := func() {
		if r != nil {
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			r = nil
		}
		if log != nil {
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			log = nil
		}
	}
	t.Cleanup(closeRunner)
	boot := func() {
		var err error
		log, _, err = wal.Open(fs, "/wal", wal.Options{SegmentBytes: 2048, KeepHeights: 2})
		if err != nil {
			t.Fatal(err)
		}
		events = &eventLog{}
		r, err = New(cfg, Deps{Chain: chain, App: &fakeApp{}, Clock: clock, WAL: log, Events: events, Rand: func(int) int { return 0 }})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Start(context.Background(), chain.Head().Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
	}
	raw := k.vote(t, 4, codec.CodePrepare, view(11, 0), b)
	assertPending := func() {
		if count, bytes := r.NextHeightUsage(); count != 1 || bytes != uint64(len(raw)) {
			t.Fatal("normal future reservation lost", count, bytes)
		}
	}
	boot()
	if !r.Receiver().Offer(transport.Inbound{Peer: k.addrs[1], Code: uint64(codec.CodePrepare), Payload: raw}) {
		t.Fatal("normal future offer refused")
	}
	r.Pump()
	assertPending()
	closeRunner()
	boot()
	assertPending()
	chain.mu.Lock()
	chain.head, chain.vs = h10.Header, next
	chain.mu.Unlock()
	r.NewHead(h10.Header)
	if !r.processOne() {
		t.Fatal("normal head input missing")
	}
	assertPending()
	closeRunner()
	boot()
	assertPending()
	snap := r.Snapshot()
	if snap.PriorSource == nil || snap.PriorSource.ValidateHead(h10.Header) != nil || !snap.PriorValidators.Contains(k.addrs[0]) || snap.PriorValidators.Contains(k.addrs[4]) || !snap.Validators.Contains(k.addrs[4]) || snap.Validators.Contains(k.addrs[0]) {
		t.Fatal("historical and successor authorities were conflated")
	}
	r.Pump()
	if r.Halted() != nil {
		t.Fatal(r.Halted())
	}
	if count, bytes := r.NextHeightUsage(); count != 0 || bytes != 0 {
		t.Fatal("released reservation not consumed", count, bytes)
	}
	outcomes := events.kinds(event.MsgOutcome)
	if len(outcomes) != 1 || outcomes[0].Fields["row"].(int) != 6 || outcomes[0].Fields["source"] != hexAddr(k.addrs[4]) || outcomes[0].Fields["check"] != "FUTURE" || r.Snapshot().Backlog != 1 {
		t.Fatal("normal joined prepare was not authenticated and backlogged at the adopted head", outcomes)
	}
	closeRunner()
	boot()
	r.Pump()
	if !r.LastReplay().Replayed || r.LastReplay().Stopped != "" {
		t.Fatal("normal released input was not replayed", r.LastReplay())
	}
	if count, bytes := r.NextHeightUsage(); count != 0 || bytes != 0 {
		t.Fatal("replay resurrected consumed reservation", count, bytes)
	}
}
