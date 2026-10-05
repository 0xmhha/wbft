package node

import (
	"encoding/hex"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/types"
)

// headerChain is a ChainReader over a few headers.
type headerChain struct{ byHash map[types.Hash]*types.Header }

func (c headerChain) Head() *types.Header                 { return nil }
func (c headerChain) HeaderByNumber(uint64) *types.Header { return nil }
func (c headerChain) Header(h types.Hash, _ uint64) *types.Header {
	return c.byHash[h]
}
func (c headerChain) HeaderByHash(h types.Hash) *types.Header { return c.byHash[h] }
func (c headerChain) HasBlock(h types.Hash, _ uint64) bool    { return c.byHash[h] != nil }

func seal(idx ...uint32) *types.AggregatedSeal {
	var s types.SealerSet
	for _, i := range idx {
		s.SetSealer(i)
	}
	return &types.AggregatedSeal{Sealers: s}
}

// TestValidatorMetrics derives the per-validator series from two headers of
// a four-validator set: block 1 decided at round 0 with three sealers, and
// block 2 decided at round 2 whose prev seals carry block 1's sealers plus
// a late one (validator 3, an extra seal).
func TestValidatorMetrics(t *testing.T) {
	addrs := []types.Address{{0xa0}, {0xa1}, {0xa2}, {0xa3}}
	vs, err := validator.NewSet(addrs, make([][]byte, 4), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	chain := headerChain{byHash: map[types.Hash]*types.Header{}}
	mk := func(n uint64, parent types.Hash, coinbase types.Address, x *types.WBFTExtra) *types.Header {
		h := &types.Header{Number: types.HeightFromUint64(n), ParentHash: parent, Coinbase: coinbase}
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		chain.byHash[codec.BlockHash(h)] = h
		return h
	}
	h0 := mk(0, types.Hash{}, types.Address{}, &types.WBFTExtra{})
	h1 := mk(1, codec.BlockHash(h0), addrs[1], &types.WBFTExtra{PreparedSeal: seal(0, 1, 2), CommittedSeal: seal(0, 1, 2)})
	h2 := mk(2, codec.BlockHash(h1), addrs[0], &types.WBFTExtra{Round: 2, PreparedSeal: seal(0, 1, 3), CommittedSeal: seal(1, 2, 3),
		PrevPreparedSeal: seal(0, 1, 2), PrevCommittedSeal: seal(0, 1, 2, 3)})

	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(chain, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil })
	m.head(h1)
	m.head(h2)
	m.head(h2) // a repeated head is not counted again
	m.head(h1) // nor an earlier one

	got := map[string]float64{}
	for _, f := range reg.Gather() {
		for _, s := range f.Samples {
			got[f.Name+"/"+s.Labels["validator"]+"/"+s.Labels["type"]] = s.Value
		}
	}
	a := func(i int) string { return "0x" + hex.EncodeToString(addrs[i][:]) }
	want := map[string]float64{
		"wbft_validator_seals_total/total/prepared":         6,
		"wbft_validator_seals_total/total/committed":        6,
		"wbft_validator_seals_total/total/prev_prepared":    3,
		"wbft_validator_seals_total/total/prev_committed":   4,
		"wbft_validator_seals_total/total/extra":            1,
		"wbft_validator_seals_total/" + a(3) + "/extra":     1,
		"wbft_validator_seals_total/" + a(3) + "/prepared":  1,
		"wbft_validator_seals_total/" + a(0) + "/committed": 1,
		// Block 2's rounds 0 and 1 after proposer a1: a2 and a3.
		"wbft_validator_missed_proposals_total/total/":        2,
		"wbft_validator_missed_proposals_total/" + a(2) + "/": 1,
		"wbft_validator_missed_proposals_total/" + a(3) + "/": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if got["wbft_validator_missed_proposals_total/"+a(1)+"/"] != 0 || got["wbft_validator_seals_total/"+a(2)+"/extra"] != 0 {
		t.Errorf("unexpected series: %v", got)
	}
}

// TestValidatorMetricsLabelLimit records only "total" for a set above the
// label limit.
func TestValidatorMetricsLabelLimit(t *testing.T) {
	addrs := make([]types.Address, validatorLabelLimit+1)
	for i := range addrs {
		addrs[i] = types.Address{byte(i), 1}
	}
	vs, err := validator.NewSet(addrs, make([][]byte, len(addrs)), types.ProposerPolicy{ID: types.RoundRobin})
	if err != nil {
		t.Fatal(err)
	}
	h := &types.Header{Number: types.HeightFromUint64(1)}
	if err := codec.SetExtra(h, &types.WBFTExtra{CommittedSeal: seal(0, 1)}); err != nil {
		t.Fatal(err)
	}
	reg := metrics.NewRegistry()
	m := newValidatorMetrics(reg)
	m.attach(headerChain{}, func(types.Height, types.Hash) (*validator.Set, error) { return vs, nil })
	m.head(h)
	for _, f := range reg.Gather() {
		for _, s := range f.Samples {
			if s.Labels["validator"] != "total" {
				t.Fatalf("a series of %s above the limit", s.Labels["validator"])
			}
			if f.Name == "wbft_validator_seals_total" && s.Value != 2 {
				t.Fatalf("total %v", s.Value)
			}
		}
	}
}
