package consensus

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// certifiedOrderBlock uses normal validator votes over a parent-linked proposal.
// The harness application remains a stub; this proves quorum seals and event
// ordering, not execution-layer state validity.
func certifiedOrderBlock(t *testing.T, h *harness, b *types.Block) *types.Block {
	t.Helper()
	var prepared, committed []types.SealEntry
	for _, i := range []int{0, 1, 2} {
		index, ok := h.vs.IndexOf(h.addrs[i])
		if !ok {
			t.Fatal("validator missing")
		}
		prepared = append(prepared, types.SealEntry{Sealer: uint32(index), Seal: h.prepare(i, view(10, 0), b).Seal})
		committed = append(committed, types.SealEntry{Sealer: uint32(index), Seal: h.commit(i, view(10, 0), b).Seal})
	}
	out, err := header.CommitHeader(b, types.Round{}, prepared, committed)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := codec.DecodeExtra(out.Header)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		seal *types.AggregatedSeal
		kind types.SealType
	}{{extra.PreparedSeal, types.PrepareSeal}, {extra.CommittedSeal, types.CommitSeal}} {
		if err := header.VerifyAggregatedSeal(h.vs, out.Header, 0, item.seal, item.kind); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestResetHeightStateCatchUpPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, RestartSafety.With(AdvanceOnCommitFailure).With(ScanReadyBacklog)} {
		for _, phase := range []StateName{Prepared, Committed} {
			for _, cause := range []string{"timeout", "f_plus_one"} {
				for _, enabled := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/%s/%s/%t", base, phase, cause, enabled), func(t *testing.T) {
						flags := base
						if enabled {
							flags = flags.With(ResetHeightState)
						}
						h := newHarness(t, 4, 1)
						h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: flags})
						h.start()
						b := h.proposal(1)
						b.Header.ParentHash = blockHash(h.env.head)
						certified := certifiedOrderBlock(t, h, b)
						if phase == Prepared {
							h.reachPrepared(b)
						} else {
							h.reachCommitted(b)
						}
						h.env.head = certified
						if cause == "timeout" {
							h.roundTimeout()
						} else {
							h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
							h.deliver(2, h.roundChange(2, view(10, 1), nil, nil, nil))
						}
						h.wantView(11, 0, AcceptRequest)
						builds := outputsOf[RequestBuild](h.out)
						wantRound := types.RoundFromUint64(1)
						if enabled {
							wantRound = types.Round{}
						}
						if len(builds) != 1 || builds[0].Height.CmpUint64(11) != 0 || builds[0].Round.Cmp(wantRound) != 0 {
							t.Fatal("builder round", builds)
						}
						if enabled {
							if len(h.broadcasts()) != 0 || h.vars().Certificate != nil || len(h.vars().RoundChanges) != 1 || h.vars().RoundChanges[0].Round != 0 || len(h.vars().RoundChanges[0].Sources) != 0 || h.vars().RoundChanges[0].PreparedRound != nil {
								t.Fatal("previous height state or target broadcast retained", h.vars(), h.broadcasts())
							}
							for _, a := range outputsOf[ArmTimer](h.out) {
								if a.Kind != RoundTimer || !a.Round.IsZero() {
									t.Fatal("unexpected timer", a)
								}
							}
						} else {
							bs := h.broadcasts()
							if len(bs) != 1 || bs[0].Msg.View.Cmp(view(11, 1)) != 0 || h.vars().Certificate == nil {
								t.Fatal("legacy behavior changed", bs)
							}
						}
						seen := false
						for _, e := range outputsOf[Event](h.out) {
							if e.Record.Kind == "ROUND_ENTER" {
								seen = true
								if e.Record.Fields["requested_round"] != "1" {
									t.Fatal("audit round lost", e.Record)
								}
							}
						}
						if !seen {
							t.Fatal("round entry event missing")
						}
						h.step(NewHead{Header: certified.Header})
						if len(h.out) != 0 {
							t.Fatal("duplicate head changed state")
						}
					})
				}
			}
		}
	}
}

func TestResetHeightStateSameHeightRound(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: RestartSafety.With(ResetHeightState)})
	h.start()
	b := h.proposal(1)
	b.Header.ParentHash = blockHash(h.env.head)
	h.reachPrepared(b)
	h.roundTimeout()
	h.wantView(10, 1, AcceptRequest)
	if h.vars().Certificate == nil || len(h.broadcasts()) != 1 || h.broadcasts()[0].Msg.View.Cmp(view(10, 1)) != 0 {
		t.Fatal("same-height prepared recovery changed")
	}
}

func TestScanReadyBacklogPair(t *testing.T) {
	for _, base := range []ImprovementSet{0, RestartSafety, RestartSafety.With(WatchCommittedImport).With(AdvanceOnCommitFailure).With(ResetHeightState)} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", base, enabled), func(t *testing.T) {
				flags := base
				if enabled {
					flags = flags.With(ScanReadyBacklog)
				}
				h := newHarness(t, 4, 1)
				h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: flags})
				h.start()
				b := h.proposal(1)
				b.Header.ParentHash = blockHash(h.env.head)
				prep := h.prepare(2, view(10, 0), b)
				commit := h.commit(2, view(10, 0), b)
				h.deliver(2, prep)
				h.deliver(2, commit)
				next := h.block(11, 2, h.addrs[0])
				next.Header.ParentHash = blockHash(b)
				futurePrepare := h.prepare(2, view(11, 0), next)
				futureCommit := h.commit(2, view(11, 0), next)
				h.deliver(2, futurePrepare)
				h.deliver(2, futureCommit)
				h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
				scheduled := outputsOf[Schedule](h.out)
				q := h.s.backlog[h.addrs[2]]
				if !enabled {
					if len(scheduled) != 0 || len(q.entries) != 4 || len(q.keys) != 4 {
						t.Fatal("legacy queue changed")
					}
					return
				}
				if len(scheduled) != 1 || len(q.entries) != 3 || len(q.keys) != 3 || q.entries[0].m.Msg.Code != codec.CodeCommit || !q.keys[keyOf(commit)] {
					t.Fatal("ready release or future retention", scheduled, q)
				}
				replay, ok := scheduled[0].In.(Replay)
				if !ok || replay.Msg.Msg.Code != codec.CodePrepare {
					t.Fatal("wrong ready message", scheduled)
				}
				h.deliver(2, commit)
				h.expect(Future, rowBacklogDropped, false)
				if len(q.entries) != 3 {
					t.Fatal("future duplicate slot lost")
				}
				h.step(replay)
				h.deliver(0, h.prepare(0, view(10, 0), b))
				h.deliver(1, h.prepare(1, view(10, 0), b))
				h.wantView(10, 0, Prepared)
				scheduled = outputsOf[Schedule](h.out)
				if len(scheduled) != 1 || len(q.entries) != 2 || len(q.keys) != 2 {
					t.Fatal("future message not released on phase change", scheduled, q)
				}
				if q.entries[0].key != keyOf(futureCommit) || q.entries[1].key != keyOf(futurePrepare) || !q.keys[keyOf(futureCommit)] || !q.keys[keyOf(futurePrepare)] {
					t.Fatal("future priority or duplicate slots changed", q)
				}
				h.step(scheduled[0].In)
				if h.s.cur.commits[h.addrs[2]] == nil {
					t.Fatal("retained commit not processed")
				}
			})
		}
	}
}
