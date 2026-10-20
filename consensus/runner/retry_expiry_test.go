package runner

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestCancelledRetryQueueJournalAndWALPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "cancel_stale"}[enabled], func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 2)
			n.timerTrace = true
			if enabled {
				n.opts.Improvements = n.opts.Improvements.With(consensus.CancelStaleRetries)
			}
			n.boot()
			n.advance(2 * time.Second)
			if n.r.Vars().View.Cmp(view(10, 1)) != 0 {
				t.Fatal("ordinary round timeout did not enter round1")
			}
			// The ordinary retry fires before a valid proposal is processed. The
			// scheduler retains its queued expiry after the proposal cancels timers.
			n.clock.advance(n.clock.now + 2*time.Second)
			if !n.r.timers.pending() {
				t.Fatal("retry expiry not queued")
			}
			n.r.d.Rand = func(n int) int { return n - 1 }
			b := block(t, 10, 1, k.addrs[1], codec.BlockHash(n.chain.head))
			rcs := []*codec.Message{}
			for _, i := range []int{0, 1, 3} {
				raw := k.sign(t, i, &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, nil)
				message, err := codec.DecodeMessage(codec.CodeRoundChange, raw)
				if err != nil {
					t.Fatal(err)
				}
				rcs = append(rcs, message)
			}
			raw := k.sign(t, 1, &codec.Message{Code: codec.CodePreprepare, View: view(10, 1), Proposal: b, RoundChanges: rcs}, nil)
			if !n.r.Receiver().Offer(transportInbound(k, 1, codec.CodePreprepare, raw, n.clock.now)) {
				t.Fatal("normal proposal not admitted")
			}
			n.r.Pump()
			if n.r.Vars().State != consensus.Preprepared || len(n.refused) != 0 {
				t.Fatal("normal proposal or signer failed", n.r.Vars(), n.refused)
			}
			retries := 0
			for _, record := range n.events.kinds(event.Send) {
				if record.Fields["cause"] == event.CauseRetry {
					retries++
				}
			}
			if enabled && retries != 0 || !enabled && retries != 1 {
				t.Fatal("queued retry behavior", retries)
			}
			if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(n.jfs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			core := consensus.NewState(n.opts)
			env := &replayEnv{head: n.chain.head}
			expiries := 0
			var queued, cancelled, popped uint64
			for _, record := range records {
				if timer, ok := record.Body.(*journal.TimerRec); ok {
					if timer.Action == "cancel" && queued != 0 {
						cancelled = timer.Sequence
					}
					if len(timer.Input) > 0 {
						decoded, err := inputlog.Decode(inputlog.KindTimeout, timer.Input, nil)
						if err != nil {
							t.Fatal(err)
						}
						timeout := decoded.(consensus.Timeout)
						if timeout.Kind == consensus.RetryTimer && timeout.Gen == 1 {
							if timeout.View.Cmp(view(10, 1)) != 0 {
								t.Fatal("timer trace lost full view")
							}
							if timer.Action == "queued" {
								queued = timer.Sequence
							}
							if timer.Action == "pop" {
								popped = timer.Sequence
							}
						}
					}
				}
				step, ok := record.Body.(*journal.StepRec)
				if !ok {
					continue
				}
				input, err := inputlog.Decode(step.InputKind, step.Input, nil)
				if err != nil {
					t.Fatal(err)
				}
				if timeout, ok := input.(consensus.Timeout); ok && timeout.Kind == consensus.RetryTimer {
					expiries++
					if timeout.View.Cmp(view(10, 1)) != 0 {
						t.Fatal("journal lost retry view")
					}
				}
				env.answers, env.err = nil, nil
				for _, raw := range step.Env {
					answer, err := inputlog.DecodeEnv(raw)
					if err != nil {
						t.Fatal(err)
					}
					env.answers = append(env.answers, answer)
				}
				var outputs []consensus.Output
				if step.InputKind == inputlog.KindStart {
					outputs = core.Step(&startEnv{head: n.chain.head, vs: k.vs}, input)
				} else {
					outputs = core.Step(env, input)
				}
				digest, err := inputlog.OutDigest(outputs)
				if err != nil || digest != step.OutDigest || env.err != nil || len(env.answers) != 0 {
					t.Fatal("journal replay diverged", step.Step, err, env.err)
				}
			}
			if expiries != 1 || queued == 0 || cancelled <= queued || popped <= cancelled {
				t.Fatal("queued/cancelled/popped expiry evidence missing", expiries, queued, cancelled, popped)
			}
			n.crash()
			n.boot()
			if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" {
				t.Fatal("WAL replay stopped", info)
			}
			n.r.timers.mu.Lock()
			armed := n.r.timers.live[consensus.RetryTimer] != nil
			n.r.timers.mu.Unlock()
			if armed == enabled {
				t.Fatal("WAL replay changed retry cancellation", armed)
			}
		})
	}
}
