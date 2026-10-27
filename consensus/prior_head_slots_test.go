package consensus

import (
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// Every vote concerns the same parent-linked block. The round-zero votes
// are signed before round one and arrive late; no signer changes its digest
// within a view. Both committed certificates therefore concern one block.
func TestBindPriorHeadNormalSlotReplacementPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			h := newHarness(t, 4, 1)
			flags := RestartSafety
			if enabled {
				flags = flags.With(BindPriorHead)
			}
			h.s = NewState(Options{Config: h.cfg, Self: h.addrs[1], Improvements: flags})
			h.start()
			b := h.proposal(1)
			b.Header.ParentHash = blockHash(h.env.head)
			h.reachPrepared(b)
			sealed := certifiedOrderBlock(t, h, b)
			latePrepare := h.prepare(3, view(10, 0), b)
			lateCommit := h.commit(3, view(10, 0), b)
			var prepares []*codec.Message
			for _, i := range []int{0, 1, 2} {
				prepares = append(prepares, h.prepare(i, view(10, 0), b))
			}
			h.roundTimeout()
			for _, i := range []int{0, 1, 2} {
				h.deliver(i, h.roundChange(i, view(10, 1), roundPtr(0), b, prepares))
			}
			broadcasts := h.broadcasts()
			if len(broadcasts) != 1 || broadcasts[0].Msg.Code != codec.CodePreprepare || blockHash(broadcasts[0].Msg.Proposal) != blockHash(b) {
				t.Fatal("normal prepared reproposal missing", broadcasts)
			}
			h.selfDeliver(broadcasts[0])
			h.selfDeliver(h.broadcasts()[0])
			h.deliver(0, h.prepare(0, view(10, 1), b))
			h.deliver(2, h.prepare(2, view(10, 1), b))
			h.wantView(10, 1, Prepared)
			h.selfDeliver(h.broadcasts()[0])
			h.deliver(0, h.commit(0, view(10, 1), b))
			h.deliver(2, h.commit(2, view(10, 1), b))
			h.wantView(10, 1, Committed)
			for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
				h.deliver(3, h.vote(3, code, view(10, 1), b))
				h.expect(ExtraSeal, rowExtraStored, true)
			}
			for _, slots := range []map[types.Address]*Verified{h.s.extraPrepare, h.s.extraCommit} {
				if v := slots[h.addrs[3]]; v == nil || v.Msg.View.Cmp(view(10, 1)) != 0 || v.Msg.Digest != blockHash(b) {
					t.Fatal("normal later-round slot was not populated")
				}
			}
			h.env.head = sealed
			h.step(NewHead{Header: sealed.Header})
			h.wantView(11, 0, AcceptRequest)
			for _, slots := range []map[types.Address]*Verified{h.s.extraPrepare, h.s.extraCommit} {
				if (slots[h.addrs[3]] == nil) != enabled {
					t.Fatal("adoption did not preserve the selected slot policy", enabled)
				}
			}
			for _, vote := range []*codec.Message{latePrepare, lateCommit} {
				h.deliver(3, vote)
				if enabled {
					h.expect(ExtraSeal, rowExtraStored, true)
				}
			}
			for _, slots := range []map[types.Address]*Verified{h.s.extraPrepare, h.s.extraCommit} {
				v := slots[h.addrs[3]]
				wantRound := types.RoundFromUint64(1)
				if enabled {
					wantRound = types.Round{}
				}
				if v == nil || v.Msg.View.Round.Cmp(wantRound) != 0 || v.Msg.Digest != codec.BlockHash(sealed.Header) {
					t.Fatal("late adopted-head vote did not replace the stale slot", enabled)
				}
			}
		})
	}
}
