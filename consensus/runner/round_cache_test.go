package runner

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// These controls cover ordinary certificate insertion and current-height local
// release through the journal and durable WAL, not physical crash recovery.
func TestRoundCacheJournalAndNormalRestartPair(t *testing.T) {
	for _, flag := range []consensus.Improvement{consensus.RefreshRoundCertificates, consensus.ClearCurrentExtraSeals} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", flag, enabled), func(t *testing.T) {
				k := newKeys(t, 4)
				self := 3
				if flag == consensus.ClearCurrentExtraSeals {
					self = 1
				}
				n := newTNode(t, k, self)
				// Keep release broadcasts consistent in both cleanup controls.
				if flag == consensus.ClearCurrentExtraSeals {
					n.opts.Improvements = n.opts.Improvements.With(consensus.BindPreparedCertificate)
				}
				if enabled {
					n.opts.Improvements = n.opts.Improvements.With(flag)
				}
				n.boot()
				b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
				if flag == consensus.RefreshRoundCertificates {
					n.advance(2 * time.Second)
					var prepares []*codec.Message
					for _, i := range []int{0, 1, 2} {
						m, err := codec.DecodeMessage(codec.CodePrepare, k.vote(t, i, codec.CodePrepare, view(10, 0), b))
						if err != nil {
							t.Fatal(err)
						}
						prepares = append(prepares, m)
					}
					round := types.Round{}
					for _, i := range []int{0, 2} {
						m := &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1), PreparedRound: &round, PreparedBlock: b, PreparedDigest: codec.BlockHash(b.Header), Prepares: prepares}
						n.deliver(i, codec.CodeRoundChange, k.sign(t, i, m, nil))
					}
					found := false
					for _, rc := range n.r.Vars().RoundChanges {
						if rc.Round == 1 && rc.PreparedBlock != nil && *rc.PreparedBlock == codec.BlockHash(b.Header) {
							found = true
						}
					}
					if !found {
						t.Fatal("ordinary prepared certificate missing")
					}
				} else {
					reachPrepared(t, n, b)
					n.deliver(3, codec.CodePrepare, k.vote(t, 3, codec.CodePrepare, view(10, 0), b))
					if len(n.r.Vars().ExtraPrepareSeals) != 1 {
						t.Fatal("ordinary late prepare missing")
					}
					n.chain.bad[codec.BlockHash(b.Header)] = true
					n.advance(2 * time.Second)
					if len(n.r.Vars().ExtraPrepareSeals) != 0 || n.r.Vars().LockedBlock != nil {
						t.Fatal("local current-height release did not complete")
					}
				}
				assertStateHygieneJournal(t, n)
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
				info := n.r.LastReplay()
				if !info.Replayed || info.Stopped != "" || info.Records == 0 || !reflect.DeepEqual(before, n.r.Vars()) || len(n.refused) != 0 {
					t.Fatal("normal durable restart changed the cache state", info, n.refused)
				}
			})
		}
	}
}
