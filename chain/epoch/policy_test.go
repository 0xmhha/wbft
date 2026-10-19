package epoch

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestReplayPolicyActivationContext(t *testing.T) {
	number := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(4))
	parent := &types.Header{Number: types.MustHeightFromBig(new(big.Int).Sub(new(big.Int).Set(number), big.NewInt(1))), Difficulty: big.NewInt(1)}
	h := &types.Header{ParentHash: codec.BlockHash(parent), Number: types.MustHeightFromBig(number)}
	c := hashEpochChain{codec.BlockHash(parent): parent}
	config := func(activation string) *types.Config {
		raw := fmt.Sprintf(`{"anzeon":{"wbft":{"epochLength":2,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"replayPerBlockPolicy":%s}}}`, activation)
		cfg, e := types.ParseChainConfig([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		return cfg
	}
	for _, activation := range []string{"null", number.String(), new(big.Int).Add(new(big.Int).Set(number), big.NewInt(1)).String()} {
		cfg := config(activation)
		got, e := ruleForEpochHeader(c, cfg, h, types.ReplayPerBlockPolicy)
		if e != nil || got != (activation == number.String()) {
			t.Fatal("full-height activation", activation, got, e)
		}
	}
	active := config(number.String())
	for _, alias := range []types.Height{types.HeightFromUint64(0), parent.Number, types.HeightFromUint64(4)} {
		bad := h.Copy()
		bad.Number = alias
		if _, e := ComputeNextEpochInfo(c, active, bad, nil); !errors.Is(e, validator.ErrUnknownAncestor) {
			t.Fatal("supplied number bypassed parent activation", alias, e)
		}
	}
	if got, e := ruleForEpochHeader(c, config("0"), &types.Header{}, types.ReplayPerBlockPolicy); e != nil || got {
		t.Fatal("genuine genesis context", got, e)
	}
}

func TestReplayPolicyConfiguredSequence(t *testing.T) {
	cfgFor := func(activation string) *types.Config {
		cfg, e := types.ParseChainConfig([]byte(`{"anzeon":{"wbft":{"epochLength":4,"proposerPolicy":0}},"transitions":[{"block":3,"proposerPolicy":1}],"wbftRules":{"consensusRules":{"replayPerBlockPolicy":` + activation + `}}}`))
		if e != nil {
			t.Fatal(e)
		}
		return cfg
	}
	entries := []types.CandidateEntry{{Addr: types.Address{1}, BLSPublicKey: []byte{1}}, {Addr: types.Address{2}, BLSPublicKey: []byte{2}}}
	ei := &types.EpochInfo{Candidates: []types.Candidate{{Addr: entries[0].Addr, Diligence: types.DefaultDiligence}, {Addr: entries[1].Addr, Diligence: types.DefaultDiligence}}, Validators: []uint32{0, 1}, BLSPublicKeys: [][]byte{{1}, {2}}}
	c := chain{}
	var parent *types.Header
	var target *types.Header
	for n := uint64(0); n <= 4; n++ {
		h := &types.Header{Number: types.HeightFromUint64(n), Difficulty: big.NewInt(1)}
		if parent != nil {
			h.ParentHash = codec.BlockHash(parent)
			h.Coinbase = entries[1].Addr
			if n == 1 {
				h.Coinbase = entries[0].Addr
			}
		}
		x := &types.WBFTExtra{GasTip: big.NewInt(0)}
		if n == 0 {
			x.EpochInfo = ei
		}
		if n > 1 {
			x.PrevPreparedSeal = bitmap(0, 1)
			x.PrevCommittedSeal = bitmap(0, 1)
		}
		if e := codec.SetExtra(h, x); e != nil {
			t.Fatal(e)
		}
		c[codec.BlockHash(h)] = h
		parent = h
		target = h
	}
	for _, activation := range []string{"null", "5", "4", "0"} {
		got, e := ComputeNextEpochInfo(c, cfgFor(activation), target, entries)
		if e != nil {
			t.Fatal(e)
		}
		want := []uint64{1_832_500, 1_907_500}
		if activation == "4" || activation == "0" {
			want[0] = 1_907_500
		}
		for i, candidate := range got.Candidates {
			if candidate.Diligence != want[i] {
				t.Fatalf("activation %s candidate %d: %d want %d", activation, i, candidate.Diligence, want[i])
			}
		}
	}
}
