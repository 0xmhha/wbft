package runner

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestActualOutcomeGenerationAndInternalInput(t *testing.T) {
	n := newTNode(t, newKeys(t, 4), 1)
	n.boot()
	block := block(t, 10, 0, n.k.addrs[0], codec.BlockHash(n.chain.head))
	payload := n.k.preprepare(t, 0, view(10, 0), block)
	n.deliver(0, codec.CodePreprepare, payload)
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	// Start a second real core incarnation, retaining the writer and
	// reusing its step numbers. Feed a recorded peer input directly so the
	// transport's already-known cache does not replace core processing.
	n.r.cfg.ReplayWAL = false
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	n.r.handle(queued{in: consensus.Message{Peer: n.k.addrs[0], Code: codec.CodePreprepare, Payload: payload}, via: viaPeer})
	n.r.Pump()
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	type scope struct{ engine, step uint64 }
	steps := map[scope]*journal.StepRec{}
	positions := map[scope]uint64{}
	for _, r := range records {
		if s, ok := r.Body.(*journal.StepRec); ok {
			key := scope{s.EngineRun, s.Step}
			steps[key] = s
			positions[key] = r.JSeq
		}
	}
	own, peer := map[uint64]int{}, map[uint64]int{}
	reused := map[uint64]map[uint64]bool{}
	for _, r := range records {
		o, ok := r.Body.(*journal.OutcomeRec)
		if !ok || o.Step == 0 {
			continue
		}
		key := scope{o.EngineRun, o.Step}
		s := steps[key]
		if o.EngineRun == 0 || s == nil || positions[key] <= r.JSeq {
			t.Fatal("outcome missing its exact following core input", r, o, s)
		}
		if o.Via != "self" {
			peer[o.EngineRun]++
			continue
		}
		in, err := inputlog.Decode(s.InputKind, s.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		msg, ok := in.(consensus.Message)
		if !ok || s.Via != "internal" || msg.Peer != n.k.addrs[1] || o.Code != uint64(msg.Code) || o.DedupKey != codec.DedupKey(msg.Payload) {
			t.Fatal("wrong self input", o, s, in)
		}
		verified, err := consensus.Recover(msg.Code, msg.Payload, nil)
		if err != nil || verified.Source != n.k.addrs[1] {
			t.Fatal("wrong signed own payload", err)
		}
		own[o.EngineRun]++
		if reused[o.Step] == nil {
			reused[o.Step] = map[uint64]bool{}
		}
		reused[o.Step][o.EngineRun] = true
	}
	if own[1] == 0 || own[2] == 0 || peer[1] == 0 || peer[2] == 0 {
		t.Fatal("both real incarnations must be exercised", own, peer)
	}
	for _, engines := range reused {
		if engines[1] && engines[2] {
			return
		}
	}
	t.Fatal("test did not exercise reused step numbers")
}
