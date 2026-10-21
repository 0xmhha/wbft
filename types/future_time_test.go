package types

import (
	"math/big"
	"testing"
)

func TestFutureTimeAllowanceInheritance(t *testing.T) {
	large := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(6))
	cfg := NewConfig(WBFTParams{AllowedFutureBlockTime: 2}, []Transition{
		{Block: big.NewInt(6), WBFT: &WBFTParams{AllowedFutureBlockTime: 3}},
		{Block: big.NewInt(10), WBFT: &WBFTParams{}},
		{Block: big.NewInt(12), WBFT: &WBFTParams{AllowedFutureBlockTime: 1}},
		{Block: large, WBFT: &WBFTParams{AllowedFutureBlockTime: 4}},
	}, GenesisInit{}, nil)
	for _, tc := range []struct {
		height *big.Int
		want   uint64
	}{
		{big.NewInt(0), 2}, {big.NewInt(5), 2}, {big.NewInt(6), 3}, {big.NewInt(7), 3},
		{big.NewInt(10), 3}, {big.NewInt(11), 3}, {big.NewInt(12), 1}, {big.NewInt(13), 1},
		{new(big.Int).Sub(large, big.NewInt(1)), 1}, {large, 4}, {new(big.Int).Add(large, big.NewInt(1)), 4},
	} {
		t.Run(tc.height.String(), func(t *testing.T) {
			h := MustHeightFromBig(tc.height)
			if got := cfg.FutureTimeAllowanceAt(h); got != tc.want {
				t.Fatal("inherited allowance", got, tc.want)
			}
			if cfg.ConfigAt(h).AllowedFutureBlockTime != 2 || cfg.Base().AllowedFutureBlockTime != 2 {
				t.Fatal("reference query or base changed")
			}
		})
	}
}

func TestFutureTimeAllowanceKeepsConfiguredTransitionOrder(t *testing.T) {
	cfg := NewConfig(WBFTParams{AllowedFutureBlockTime: 1}, []Transition{
		{Block: big.NewInt(6), WBFT: &WBFTParams{AllowedFutureBlockTime: 2}},
		{Block: big.NewInt(6), WBFT: &WBFTParams{AllowedFutureBlockTime: 3}},
		{Block: big.NewInt(6), WBFT: &WBFTParams{}},
	}, GenesisInit{}, nil)
	ordered := cfg.Transitions()
	var want uint64 = 1
	for _, tr := range ordered {
		if tr.WBFT.AllowedFutureBlockTime != 0 {
			want = tr.WBFT.AllowedFutureBlockTime
		}
	}
	if got := cfg.FutureTimeAllowanceAt(HeightFromUint64(6)); got != want {
		t.Fatal("configured order was changed", got, want)
	}
	ordered[0].WBFT.AllowedFutureBlockTime = 8
	if got := cfg.FutureTimeAllowanceAt(HeightFromUint64(6)); got != want {
		t.Fatal("caller copy changed configuration", got, want)
	}
}
