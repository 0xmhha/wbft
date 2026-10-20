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

// A normal manual clock expiry and a synchronized Stop/Start compare the
// local cap. There are no forged messages or physical crash claims.
func TestInitialRoundCapJournalAndNormalRestartPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			n.timerTrace = true
			policy, cap := uint64(0), uint64(4)
			n.opts.Config = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 1000, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: &cap}, nil, types.GenesisInit{}, nil)
			if enabled {
				n.opts.Improvements = n.opts.Improvements.With(consensus.CapInitialRoundTimeout)
			}
			n.boot()
			if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(n.jfs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			want := 1000 * time.Second
			if enabled {
				want = 4 * time.Second
			}
			found := false
			for _, record := range records {
				if timer, ok := record.Body.(*journal.TimerRec); ok && timer.Action == "arm" {
					in, err := inputlog.Decode(inputlog.KindTimeout, timer.Input, nil)
					if err != nil {
						t.Fatal(err)
					}
					timeout := in.(consensus.Timeout)
					if timeout.Kind == consensus.RoundTimer && timeout.View.Cmp(view(10, 0)) == 0 {
						found = true
						if timer.Deadline-timer.EntryMono != want {
							t.Fatal("timer deadline lost", timer, want)
						}
					}
				}
			}
			if !found {
				t.Fatal("round timer journal missing")
			}
			// A normal signed vote gives both modes a durable input before restart.
			b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
			n.deliver(0, codec.CodePrepare, k.vote(t, 0, codec.CodePrepare, view(10, 0), b))
			n.advance(4 * time.Second)
			round, wantRC := uint64(0), 0
			if enabled {
				round, wantRC = 1, 1
			}
			if n.r.Vars().View.Cmp(view(10, round)) != 0 || len(n.net.own(codec.CodeRoundChange)) != wantRC {
				t.Fatal("ordinary first expiry used the wrong policy", n.r.Vars())
			}
			assertStateHygieneJournal(t, n)
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
				t.Fatal("normal synchronized restart changed capped policy", info, n.refused)
			}
			if err = n.r.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
