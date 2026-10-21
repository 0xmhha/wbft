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
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// Only the local clock and application wait differ. Normal signed messages,
// certificates and synchronized Stop/Start establish the journal/replay pair.
func TestFutureWaitLimitJournalAndNormalRestartPairs(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, long := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("local=%t/long=%t/limit=%t", local, long, enabled), func(t *testing.T) {
					k := newKeys(t, 4)
					n := newTNode(t, k, 1)
					n.timerTrace = true
					if local {
						n.opts.Improvements = n.opts.Improvements.With(consensus.ValidateRoundProposals)
					}
					if enabled {
						n.opts.Improvements = n.opts.Improvements.With(consensus.LimitFutureProposalWait)
					}
					n.boot()
					if local {
						n.advance(2 * time.Second)
					}
					b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
					wait := 500 * time.Millisecond
					if long {
						wait = 3 * time.Second
						if local {
							wait = 5 * time.Second
						}
					}
					n.chain.future[codec.BlockHash(b.Header)] = n.clock.Mono() + wait
					if local {
						var prepares []*codec.Message
						for _, i := range []int{0, 2, 3} {
							m, err := codec.DecodeMessage(codec.CodePrepare, k.vote(t, i, codec.CodePrepare, view(10, 0), b))
							if err != nil {
								t.Fatal(err)
							}
							prepares = append(prepares, m)
						}
						round := types.Round{}
						// Self already stored its normal round change. Two peers
						// complete one quorum without another proposal attempt.
						for _, i := range []int{0, 2} {
							m := &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1), PreparedRound: &round, PreparedBlock: b, PreparedDigest: codec.BlockHash(b.Header), Prepares: prepares}
							n.deliver(i, codec.CodeRoundChange, k.sign(t, i, m, nil))
						}
					} else {
						n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
					}
					blocked := enabled && long
					if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
						t.Fatal(err)
					}
					assertStateHygieneJournal(t, n)
					records, err := journal.ReadAll(n.jfs, "/j")
					if err != nil {
						t.Fatal(err)
					}
					kind := consensus.FutureTimer
					if local {
						kind = consensus.RoundProposalTimer
					}
					armed := 0
					for _, rec := range records {
						timer, ok := rec.Body.(*journal.TimerRec)
						if !ok || timer.Action != "arm" {
							continue
						}
						in, err := inputlog.Decode(inputlog.KindTimeout, timer.Input, nil)
						if err != nil {
							t.Fatal(err)
						}
						if in.(consensus.Timeout).Kind == kind {
							armed++
							if timer.Deadline-timer.EntryMono != wait {
								t.Fatal("future wait deadline changed", timer)
							}
						}
					}
					if (armed == 1) == blocked || armed > 1 {
						t.Fatal("wait journal policy", armed, blocked)
					}
					health := 0
					for _, e := range n.events.kinds(event.Health) {
						if e.Fields["what"] == "future_proposal_wait_exceeded" {
							health++
						}
					}
					if (health == 1) != blocked || health > 1 {
						t.Fatal("wait limit observation", health, blocked)
					}
					before := n.r.Vars()
					if err = n.log.Sync(); err != nil {
						t.Fatal(err)
					}
					if err = n.r.Stop(); err != nil {
						t.Fatal(err)
					}
					if err = n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
						t.Fatal(err)
					}
					n.r.Pump()
					if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" || !reflect.DeepEqual(before, n.r.Vars()) || len(n.refused) != 0 {
						t.Fatal("normal restart changed wait policy", info, n.refused)
					}
					if !long {
						n.advance(wait)
						code := codec.CodePrepare
						if local {
							code = codec.CodePreprepare
						}
						if len(n.net.own(code)) != 1 || len(n.refused) != 0 {
							t.Fatal("short normal wait did not revalidate once", n.r.Vars(), n.refused)
						}
					}
					if err = n.r.Stop(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
