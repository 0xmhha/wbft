package source

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

func snap(t *testing.T, i byte) *AuthoritySnapshot {
	t.Helper()
	s, err := NewAuthoritySnapshot(types.HeightFromUint64(uint64(i)), types.Hash{i}, uint256.NewInt(7),
		[]types.Address{{2}, {1}, {1}}, []types.Address{{2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshot(t *testing.T) {
	s := snap(t, 1)
	if s.Eligibility(types.Address{2}) != types.Ineligible || s.Eligibility(types.Address{1}) != types.Eligible ||
		s.Eligibility(types.Address{3}) != types.Unknown {
		t.Error("eligibility")
	}
	if len(s.Scope()) != 2 || s.GasTip().Uint64() != 7 {
		t.Error("scope or gas tip")
	}
	if _, err := NewAuthoritySnapshot(types.Height{}, types.Hash{}, nil, nil, nil, nil); !errors.Is(err, ErrNilGasTip) {
		t.Errorf("nil gas tip: %v", err)
	}
	if _, err := NewAuthoritySnapshot(types.Height{}, types.Hash{}, uint256.NewInt(0), nil, []types.Address{{9}}, nil); !errors.Is(err, ErrBlacklistedNotScope) {
		t.Errorf("blacklist outside scope: %v", err)
	}
	if _, err := GasTipFromBig(big.NewInt(-1)); err == nil {
		t.Error("negative gas tip")
	}
	if v, err := GasTipFromBig(big.NewInt(27)); err != nil || v.Uint64() != 27 {
		t.Error("gas tip conversion")
	}
}

func TestCache(t *testing.T) {
	c := NewCache(2)
	c.Put(snap(t, 1))
	c.Put(snap(t, 2))
	c.Put(snap(t, 3))
	if _, ok := c.Get(types.Hash{1}); ok || c.Len() != 2 {
		t.Error("oldest snapshot not evicted")
	}
	if _, ok := c.Get(types.Hash{3}); !ok {
		t.Error("newest snapshot missing")
	}
	snaps := make([]*AuthoritySnapshot, 80)
	for i := range snaps {
		snaps[i] = snap(t, byte(i))
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Put(snaps[i*10+j%10])
				c.Get(types.Hash{byte(j)})
			}
		}(i)
	}
	wg.Wait()
	if c.Len() > 2 {
		t.Errorf("cache holds %d", c.Len())
	}
}
