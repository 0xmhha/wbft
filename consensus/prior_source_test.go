package consensus

import (
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestPriorHeadSourceHistoricalQueryAndCopies(t *testing.T) {
	h := newHarness(t, 4, 1)
	b := h.proposal(1)
	b.Header.ParentHash = blockHash(h.env.head)
	sealed := certifiedOrderBlock(t, h, b)
	p, err := NewPriorHeadSource(sealed.Header, h.vs)
	if err != nil || p.ValidateHead(sealed.Header) != nil {
		t.Fatal("normal adopted source", p, err)
	}
	if !p.MatchesLookup(sealed.Header.Number, sealed.Header.ParentHash) || p.MatchesLookup(sealed.Header.Number.AddUint64(1), blockHash(sealed)) {
		t.Fatal("historical and successor query conflated")
	}
	other := h.proposal(2)
	other.Header.ParentHash = sealed.Header.ParentHash
	if p.ValidateHead(other.Header) == nil {
		t.Fatal("another normal candidate matched adopted source")
	}
	copy := p.Copy()
	copy.Number = copy.Number.AddUint64(1)
	if p.Number.Cmp(sealed.Header.Number) != 0 || copy.Number.Cmp(p.Number) == 0 {
		t.Fatal("source copy aliases metadata")
	}
	if p.Hash != codec.BlockHash(sealed.Header) || p.Validators != h.vs {
		t.Fatal("source identity changed")
	}
}

func TestPriorHeadSourceDistinguishesCommittedRounds(t *testing.T) {
	h := newHarness(t, 4, 1)
	b := h.proposal(3)
	b.Header.ParentHash = blockHash(h.env.head)
	var heads []*types.Header
	for _, round := range []uint64{0, 1} {
		v := view(10, round)
		var prepares, commits []types.SealEntry
		for _, i := range []int{0, 1, 2} {
			index, ok := h.vs.IndexOf(h.addrs[i])
			if !ok {
				t.Fatal("member absent")
			}
			prepares = append(prepares, types.SealEntry{Sealer: uint32(index), Seal: h.prepare(i, v, b).Seal})
			commits = append(commits, types.SealEntry{Sealer: uint32(index), Seal: h.commit(i, v, b).Seal})
		}
		sealed, err := header.CommitHeader(b, v.Round, prepares, commits)
		if err != nil {
			t.Fatal(err)
		}
		x, err := codec.DecodeConsensusExtra(sealed.Header)
		if err != nil || header.VerifyAggregatedSeal(h.vs, sealed.Header, x.Round, x.PreparedSeal, types.PrepareSeal) != nil || header.VerifyAggregatedSeal(h.vs, sealed.Header, x.Round, x.CommittedSeal, types.CommitSeal) != nil {
			t.Fatal("normal quorum did not verify", err)
		}
		heads = append(heads, sealed.Header)
	}
	if codec.BlockHash(heads[0]) != codec.BlockHash(heads[1]) {
		t.Fatal("ordinary committed-round variants changed block identity")
	}
	p, err := NewPriorHeadSource(heads[0], h.vs)
	if err != nil || p.ValidateHead(heads[0]) != nil || p.ValidateHead(heads[1]) == nil {
		t.Fatal("explicit committed round was lost", err)
	}
}

func TestPriorHeadSourceFullHeightAndUnavailable(t *testing.T) {
	h := newHarness(t, 4, 1)
	head := h.env.head.Header.Copy()
	n, err := types.HeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 90), big.NewInt(9)))
	if err != nil {
		t.Fatal(err)
	}
	head.Number = n
	p, err := NewPriorHeadSource(head, nil)
	if err != nil || p.Validators != nil || p.ValidateHead(head) != nil || !p.MatchesLookup(n, head.ParentHash) || p.MatchesLookup(types.HeightFromUint64(9), head.ParentHash) {
		t.Fatal("full height or unavailable source lost", err)
	}
	empty, err := validator.NewSet(nil, nil, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	known, err := NewPriorHeadSource(head, empty)
	if err != nil || known.Validators == nil || known.Validators.Len() != 0 {
		t.Fatal("known-empty conflated with unavailable", err)
	}
}
