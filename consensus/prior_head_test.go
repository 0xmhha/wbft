package consensus

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

type priorPairEnv struct {
	*fakeEnv
	head        *types.Header
	past, next  *validator.Set
	unavailable bool
}

func (e *priorPairEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	if n.Cmp(e.head.Number) == 0 && parent == e.head.ParentHash {
		if e.unavailable {
			return nil, errors.New("normal historical source unavailable")
		}
		return e.past, nil
	}
	if n.Cmp(e.head.Number.AddUint64(1)) == 0 && parent == codec.BlockHash(e.head) {
		return e.next, nil
	}
	return e.fakeEnv.ValidatorsAt(n, parent)
}

func TestBindPriorHeadCommittedRoundPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		h := newHarness(t, 4, 1)
		flags := ImprovementSet(0)
		if enabled {
			flags = flags.With(BindPriorHead)
		}
		h.s = NewState(Options{Config: h.cfg, Self: h.addrs[1], Improvements: flags})
		h.start()
		b := h.proposal(1)
		b.Header.ParentHash = blockHash(h.env.head)
		h.reachPrepared(b)
		h.roundTimeout()
		h.wantView(10, 1, AcceptRequest)
		sealed := certifiedOrderBlock(t, h, b)
		h.env.head = sealed
		h.step(NewHead{Header: sealed.Header})
		h.wantView(11, 0, AcceptRequest)
		want := types.RoundFromUint64(1)
		if enabled {
			want = types.Round{}
		}
		if h.s.prior.round.Cmp(want) != 0 {
			t.Fatal("adopted round or disabled behavior changed", enabled, h.vars())
		}
		if enabled {
			p := h.s.Snapshot().PriorSource
			if p == nil || p.ValidateHead(sealed.Header) != nil || p.Validators == nil || h.s.prior.proposal == nil {
				t.Fatal("adopted source missing")
			}
		}
		h.deliver(0, h.prepare(0, view(10, 0), b))
		if (len(h.s.Snapshot().ExtraPrepare) != 0) != enabled {
			t.Fatal("late normal vote did not use adopted round", enabled)
		}
	}
}

func TestBindPriorHeadHistoricalMembershipAndUnavailable(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		h := newHarness(t, 4, 1)
		h.s = NewState(Options{Config: h.cfg, Self: h.addrs[1], Improvements: ImprovementSet(0).With(BindPriorHead)})
		h.start()
		b := h.proposal(1)
		b.Header.ParentHash = blockHash(h.env.head)
		sealed := certifiedOrderBlock(t, h, b)
		var addresses []types.Address
		var keys [][]byte
		for _, i := range []int{1, 2, 3} {
			addresses = append(addresses, h.addrs[i])
			keys = append(keys, h.blsK[i].PublicKey().Bytes())
		}
		next, err := validator.NewSet(addresses, keys, types.ProposerPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		h.env.head = sealed
		env := &priorPairEnv{fakeEnv: h.env, head: sealed.Header, past: h.vs, next: next, unavailable: unavailable}
		h.out = h.s.Step(env, NewHead{Header: sealed.Header})
		h.wantView(11, 0, AcceptRequest)
		snapshot := h.s.Snapshot()
		if snapshot.Validators.Len() != 3 || snapshot.PriorSource == nil || snapshot.PriorSource.ValidateHead(sealed.Header) != nil {
			t.Fatal("separate query identities lost")
		}
		if unavailable {
			if snapshot.PriorSource.Validators != nil || snapshot.PriorValidators == nil || snapshot.PriorValidators.Len() != 0 || h.s.prior.proposal != nil {
				t.Fatal("unavailable history fell back to current membership")
			}
		} else if snapshot.PriorValidators.Len() != 4 || !snapshot.PriorValidators.Contains(h.addrs[0]) || snapshot.Validators.Contains(h.addrs[0]) {
			t.Fatal("historical member replaced by successor")
		}
		h.deliver(0, h.prepare(0, view(10, 0), b))
		if (len(h.s.Snapshot().ExtraPrepare) == 1) != !unavailable {
			t.Fatal("historical normal vote eligibility conflated")
		}
	}
}
