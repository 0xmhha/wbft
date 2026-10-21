package runner

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// A normal signed proposal arrives after advancing the local manual clock.
// The test measures actual reservations and synchronized operator restarts.
func TestAcceptedProposalDeadlineJournalAndRestartPair(t *testing.T) {
	for _, base := range []consensus.ImprovementSet{consensus.RestartSafety, consensus.KnownImprovements() &^ consensus.ImprovementSet(0).With(consensus.PreserveRoundDeadline)} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", base, enabled), func(t *testing.T) {
				k := newKeys(t, 4)
				n := newTNode(t, k, 1)
				n.timerTrace = true
				// The normal parent/proposal seconds precede this local clock.
				origin := 10 * time.Second
				n.clock.now = origin
				n.opts.Improvements = base
				if enabled {
					n.opts.Improvements = n.opts.Improvements.With(consensus.PreserveRoundDeadline)
				}
				n.boot()
				initial := n.r.timers.live[consensus.RoundTimer]
				if initial == nil || initial.t.(mTimer).e.at != origin+2*time.Second {
					t.Fatal("initial reservation missing")
				}
				n.advance(1900 * time.Millisecond)
				b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
				m := &codec.Message{Code: codec.CodePreprepare, View: view(10, 0), Proposal: b}
				n.deliver(0, codec.CodePreprepare, k.sign(t, 0, m, nil))
				current := n.r.timers.live[consensus.RoundTimer]
				want := origin + 3900*time.Millisecond
				if enabled {
					want = origin + 2*time.Second
				}
				if current == nil || current.t.(mTimer).e.at != want || (current == initial) != enabled || n.r.Snapshot().State != consensus.Preprepared {
					t.Fatal("accepted proposal changed deadline incorrectly", current, want, n.r.Snapshot())
				}
				assertRoundDeadlineJournalRuns(t, n, 1)
				n.advance(100 * time.Millisecond)
				wantRound := uint64(0)
				if enabled {
					wantRound = 1
				}
				if n.r.Vars().View.Cmp(view(10, wantRound)) != 0 {
					t.Fatal("original deadline expiry used another policy", n.r.Vars())
				}
				before := n.r.Vars()
				if err := n.log.Sync(); err != nil {
					t.Fatal(err)
				}
				if err := n.r.Stop(); err != nil {
					t.Fatal(err)
				}
				if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
					t.Fatal(err)
				}
				n.r.Pump()
				// Existing replay restores a reservation in the new run. This
				// does not assert an unchanged physical deadline across runs.
				if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" || !reflect.DeepEqual(before, n.r.Vars()) || len(n.refused) != 0 {
					t.Fatal("normal replay changed selected state", info, n.refused)
				}
				if !initial.done {
					t.Fatal("old reservation survived normal stop")
				}
				assertRoundDeadlineJournalRuns(t, n, 2)
				if err := n.r.Stop(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Each normal engine start has a fresh state and its recorded timer generations.
// Check all runs, including the original stopped run, without changing records.
func assertRoundDeadlineJournalRuns(t *testing.T, n *tnode, wantRuns int) {
	t.Helper()
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	var core *consensus.State
	var engine uint64
	runs, steps := 0, 0
	env := &replayEnv{head: n.chain.head}
	for _, record := range records {
		step, ok := record.Body.(*journal.StepRec)
		if !ok {
			continue
		}
		input, err := inputlog.Decode(step.InputKind, step.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		env.answers, env.err = nil, nil
		for _, raw := range step.Env {
			answer, err := inputlog.DecodeEnv(raw)
			if err != nil {
				t.Fatal(err)
			}
			env.answers = append(env.answers, answer)
		}
		var out []consensus.Output
		if step.InputKind == inputlog.KindStart {
			if step.Step != 1 || step.EngineRun <= engine {
				t.Fatal("invalid normal run boundary", step)
			}
			engine, runs = step.EngineRun, runs+1
			core = consensus.NewState(n.opts)
			if err := core.RestoreTimerGenerations(step.TimerGens); err != nil {
				t.Fatal(err)
			}
			out = core.Step(&startEnv{head: n.chain.head, vs: n.k.vs}, input)
		} else {
			if core == nil || step.EngineRun != engine {
				t.Fatal("step lost engine ownership", step)
			}
			out = core.Step(env, input)
		}
		digest, err := inputlog.OutDigest(out)
		if err != nil || digest != step.OutDigest || env.err != nil || len(env.answers) != 0 {
			t.Fatal("run journal replay diverged", step.EngineRun, step.Step, err, env.err)
		}
		steps++
	}
	if runs != wantRuns || steps == 0 || core == nil || !reflect.DeepEqual(core.Vars(), n.r.Vars()) {
		t.Fatal("normal run journal state differs", runs, wantRuns, steps)
	}
}
