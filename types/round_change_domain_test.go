package types

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
)

func domainConfig(t *testing.T, activation string) *Config {
	t.Helper()
	raw := fmt.Sprintf(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":%s}}}`, activation)
	c, err := ParseChainConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundChangeDomainIdentityCopyAndFullHeight(t *testing.T) {
	id := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(7))
	at := MustHeightFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 80), big.NewInt(3)))
	d, err := NewRoundChangeDomain(id, Hash{1}, at)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Set(id)
	id.SetInt64(1)
	d.ChainID().SetInt64(2)
	d.Activation().Big().SetInt64(0)
	copy := d.Copy()
	if d.ChainID().Cmp(want) != 0 || d.Activation().Cmp(at) != 0 || !d.Equal(copy) || d == copy {
		t.Fatal("domain aliases caller storage")
	}
	before, _ := at.Sub(HeightFromUint64(1))
	if d.Active(before) || !d.Active(at) || !d.Active(at.AddUint64(1)) || d.Active(HeightFromUint64(3)) {
		t.Fatal("activation lost full height")
	}
	zero := new(RoundChangeDomain)
	if zero.Validate() == nil || zero.Copy().Validate() == nil || zero.Equal(zero) || zero.Active(at) {
		t.Fatal("zero domain granted capability")
	}
	var legacy *RoundChangeDomain
	if legacy.Validate() != nil || legacy.Copy() != nil || !legacy.Equal(nil) || legacy.Active(at) {
		t.Fatal("nil legacy contract changed")
	}
}

func TestRoundChangeDomainCommonRuleAndMissingContext(t *testing.T) {
	c := domainConfig(t, "18446744073709551619")
	if ValidateRoundChangeDomain(c, nil) == nil {
		t.Fatal("future activation accepted without context")
	}
	d, err := DomainForConfig(c, Hash{2})
	if err != nil || ValidateRoundChangeDomain(c, d) != nil {
		t.Fatal("matching profile refused", err)
	}
	if _, err := DomainForConfig(c, Hash{}); !errors.Is(err, ErrRoundChangeDomain) {
		t.Fatal("missing verified genesis accepted", err)
	}
	if ValidateRoundChangeDomain(domainConfig(t, "3"), d) == nil || ValidateRoundChangeDomain(domainConfig(t, "null"), d) == nil {
		t.Fatal("context was rebound to a different rule")
	}
	for _, id := range []*big.Int{nil, new(big.Int), big.NewInt(-1)} {
		if _, err := NewRoundChangeDomain(id, Hash{1}, HeightFromUint64(1)); !errors.Is(err, ErrRoundChangeDomain) {
			t.Fatal("nonpositive chain identity accepted")
		}
	}
	for _, bad := range []string{"0", "-1", `"3"`, "1.5"} {
		raw := fmt.Sprintf(`{"wbftRules":{"consensusRules":{"roundChangeDomain":%s}}}`, bad)
		if _, err := ParseChainConfig([]byte(raw)); err == nil {
			t.Fatalf("invalid activation accepted: %s", bad)
		}
	}
	off := domainConfig(t, "null")
	if domain, err := DomainForConfig(off, Hash{}); err != nil || domain != nil || ValidateRoundChangeDomain(off, nil) != nil {
		t.Fatal("null rule did not disable behavior", err)
	}
}
