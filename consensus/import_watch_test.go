package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func importHarness(t *testing.T, flags ImprovementSet) (*harness, *types.Block) {
	t.Helper()
	h := newHarness(t, 4, 1)
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[h.self], Improvements: flags})
	h.start()
	b := h.proposal(1)
	h.reachCommitted(b)
	return h, b
}

func boundImportResult(b *types.Block, err error) CommitResult {
	v := view(10, 0)
	return CommitResult{Hash: blockHash(b), Err: err, View: &v}
}

func TestImportWatchdogPendingAndLegacyPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "watchdog"}[enabled], func(t *testing.T) {
			flags := ImprovementSet(0)
			if enabled {
				flags = flags.With(WatchCommittedImport)
			}
			h, b := importHarness(t, flags)
			oldGen := h.s.gen[RoundTimer]
			decisionArms := outputsOf[ArmTimer](h.out)
			if (len(decisionArms) == 1) != enabled {
				t.Fatal("decision monitor selection", decisionArms)
			}
			for i := 0; i < 3; i++ {
				h.roundTimeout()
				if !enabled {
					h.wantView(10, uint64(i+1), AcceptRequest)
					continue
				}
				h.wantView(10, 0, Committed)
				if len(h.broadcasts()) != 0 || len(outputsOf[Commit](h.out)) != 0 {
					t.Fatal("pending import emitted consensus action")
				}
				arms := outputsOf[ArmTimer](h.out)
				if len(arms) != 1 || arms[0].Duration != 2*time.Second || arms[0].Gen <= oldGen {
					t.Fatal("monitor not renewed", arms)
				}
				oldGen = arms[0].Gen
			}
			if enabled {
				h.step(CommitResult{Hash: blockHash(b)})
				if len(h.out) != 0 || !h.s.roundLive {
					t.Fatal("unbound historical result consumed")
				}
			}
		})
	}
}

func TestImportWatchdogSuccessWaitsForHead(t *testing.T) {
	h, b := importHarness(t, ImprovementSet(0).With(WatchCommittedImport).With(AdvanceOnCommitFailure))
	gen := h.s.gen[RoundTimer]
	h.step(boundImportResult(b, nil))
	if h.s.roundLive || len(outputsOf[CancelTimers](h.out)) != 1 {
		t.Fatal("success did not cancel monitor")
	}
	h.wantView(10, 0, Committed)
	if len(h.step(Timeout{Kind: RoundTimer, Gen: gen})) != 0 {
		t.Fatal("queued timer changed completed import")
	}
	if len(h.step(boundImportResult(b, errors.New("duplicate failure")))) != 0 {
		t.Fatal("duplicate result changed view")
	}
	h.env.head = b
	h.step(NewHead{Header: b.Header})
	h.wantView(11, 0, AcceptRequest)
	if len(h.broadcasts()) != 0 || h.vars().Certificate != nil {
		t.Fatal("new head did not clear previous view")
	}
}

func TestImportFailureOptionAndViewBinding(t *testing.T) {
	for _, flags := range []ImprovementSet{0, ImprovementSet(0).With(WatchCommittedImport), ImprovementSet(0).With(AdvanceOnCommitFailure), ImprovementSet(0).With(WatchCommittedImport).With(AdvanceOnCommitFailure)} {
		t.Run(testFlagName(flags), func(t *testing.T) {
			h, b := importHarness(t, flags)
			for _, result := range []CommitResult{
				{Hash: types.Hash{9}, Err: errors.New("other block"), View: ptrView(view(10, 0))},
				{Hash: blockHash(b), Err: errors.New("old round"), View: ptrView(view(10, 1))},
				{Hash: blockHash(b), Err: errors.New("old sequence"), View: ptrView(view(9, 0))},
				{Hash: blockHash(b), Err: errors.New("unbound")},
			} {
				if len(h.step(result)) != 0 {
					t.Fatal("unbound result emitted action", result)
				}
				h.wantView(10, 0, Committed)
			}
			h.step(boundImportResult(b, errors.New("ordinary import failure")))
			if !flags.Has(AdvanceOnCommitFailure) {
				h.wantView(10, 0, Committed)
				return
			}
			h.wantView(10, 1, AcceptRequest)
			if len(h.broadcasts()) != 1 || h.broadcasts()[0].Msg.Code != codec.CodeRoundChange {
				t.Fatal("failure did not announce next round")
			}
			found := false
			for _, e := range outputsOf[Event](h.out) {
				if e.Record.Kind == event.RoundEnter && e.Record.Fields["cause"] == event.CauseFinalizeFail {
					found = true
				}
			}
			if !found {
				t.Fatal("failure reported as timeout")
			}
			if len(h.step(boundImportResult(b, nil))) != 0 {
				t.Fatal("late success changed new round")
			}
		})
	}
}

func testFlagName(flags ImprovementSet) string {
	if flags == 0 {
		return "legacy"
	}
	return flags.Names()[0] + map[bool]string{false: "", true: "_both"}[flags.Has(WatchCommittedImport) && flags.Has(AdvanceOnCommitFailure)]
}

func ptrView(v types.View) *types.View { return &v }

func TestImportWatchdogBadBlockAndFPlusOneStillRecover(t *testing.T) {
	for _, bad := range []bool{false, true} {
		h, b := importHarness(t, ImprovementSet(0).With(WatchCommittedImport))
		if bad {
			h.env.bad[blockHash(b)] = true
			h.roundTimeout()
			h.wantView(10, 1, AcceptRequest)
			if h.vars().LockedBlock != nil || len(h.broadcasts()) != 1 {
				t.Fatal("bad block not released")
			}
		} else {
			for _, i := range []int{2, 3} {
				h.deliver(i, h.roundChange(i, view(10, 1), nil, nil, nil))
			}
			h.wantView(10, 1, AcceptRequest)
			if h.vars().LockedBlock == nil || *h.vars().LockedBlock != blockHash(b) {
				t.Fatal("F+1 lost the valid lock")
			}
		}
	}
}

func TestImportWatchdogHeadCatchupAndRestartIsolation(t *testing.T) {
	for _, byResult := range []bool{false, true} {
		h, b := importHarness(t, ImprovementSet(0).With(WatchCommittedImport).With(AdvanceOnCommitFailure))
		h.env.head = b
		if byResult {
			h.step(boundImportResult(b, errors.New("late result")))
		} else {
			h.roundTimeout()
		}
		h.wantView(11, 0, AcceptRequest)
		if len(h.broadcasts()) != 0 || h.vars().Certificate != nil {
			t.Fatal("catchup retained old vote state")
		}
		build := outputsOf[RequestBuild](h.out)
		if len(build) != 1 || !build[0].Round.IsZero() {
			t.Fatal("catchup builder round", build)
		}
		gen := h.s.gen[RoundTimer]
		h.step(Stop{})
		h.start()
		if len(h.step(boundImportResult(b, nil))) != 0 || len(h.step(Timeout{Kind: RoundTimer, Gen: gen})) != 0 {
			t.Fatal("previous run input changed new sequence")
		}
	}
}

func TestImportFailureDoesNotChangeCommitHeaderFailure(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.s = NewState(Options{Config: h.cfg, Self: h.addrs[1], Improvements: ImprovementSet(0).With(WatchCommittedImport).With(AdvanceOnCommitFailure)})
	h.start()
	b := h.proposal(1)
	h.reachPrepared(b)
	h.selfDeliver(h.broadcasts()[0])
	h.deliver(0, h.commit(0, view(10, 0), b))
	h.env.finalizeFail = true
	h.deliver(2, h.commit(2, view(10, 0), b))
	if h.s.cur.importHash != nil || len(outputsOf[Commit](h.out)) != 0 || len(h.broadcasts()) != 1 {
		t.Fatal("header failure treated as pending import")
	}
	h.wantView(10, 0, Committed)
}
