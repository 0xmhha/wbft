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

// Normal signed certificates, a manual clock and an explicit WAL sync
// establish journal/restart behavior; this is not physical crash recovery.
func TestRoundProposalWaitJournalAndNormalRestartPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			n.timerTrace = true
			if enabled {
				n.opts.Improvements = n.opts.Improvements.With(consensus.ValidateRoundProposals)
			}
			n.boot()
			n.advance(2 * time.Second)
			b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
			n.chain.future[codec.BlockHash(b.Header)] = n.clock.Mono() + 500*time.Millisecond
			var prepares []*codec.Message
			for _, i := range []int{0, 2, 3} {
				m, err := codec.DecodeMessage(codec.CodePrepare, k.vote(t, i, codec.CodePrepare, view(10, 0), b))
				if err != nil {
					t.Fatal(err)
				}
				prepares = append(prepares, m)
			}
			round := types.Round{}
			for _, i := range []int{0, 2, 3} {
				m := &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1), PreparedRound: &round, PreparedBlock: b, PreparedDigest: codec.BlockHash(b.Header), Prepares: prepares}
				n.deliver(i, codec.CodeRoundChange, k.sign(t, i, m, nil))
			}
			want := 1
			if enabled {
				want = 0
			}
			if len(n.net.own(codec.CodePreprepare)) != want || (n.r.Vars().RoundProposalWait != nil) != enabled {
				t.Fatal("local clock wait did not retain its selected behavior", n.r.Vars())
			}
			assertStateHygieneJournal(t, n)
			records, err := journal.ReadAll(n.jfs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			localArmed, extendedCancel := false, false
			for _, record := range records {
				if timer, ok := record.Body.(*journal.TimerRec); ok {
					if timer.Action == "cancel" && len(timer.Kinds) == 4 {
						extendedCancel = true
					}
					if timer.Action == "arm" {
						in, err := inputlog.Decode(inputlog.KindTimeout, timer.Input, nil)
						if err != nil {
							t.Fatal(err)
						}
						if in.(consensus.Timeout).Kind == consensus.RoundProposalTimer {
							localArmed = true
						}
					}
				}
			}
			if localArmed != enabled || extendedCancel != enabled {
				t.Fatal("local timer journal capability lost", localArmed, extendedCancel)
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
			if info := n.r.LastReplay(); !info.Replayed || info.Stopped != "" || !reflect.DeepEqual(before, n.r.Vars()) || len(n.refused) != 0 {
				t.Fatal("normal durable restart lost the local wait", info, n.refused)
			}
			n.advance(500 * time.Millisecond)
			if len(n.net.own(codec.CodePreprepare)) != 1 || n.r.Vars().RoundProposalWait != nil || len(n.refused) != 0 {
				t.Fatal("normal timestamp release did not produce exactly one proposal", n.r.Vars(), n.refused)
			}
		})
	}
}
