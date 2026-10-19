package types

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func ruleConfig(t testing.TB, extra string) *Config {
	t.Helper()
	c, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{"epochLength":100}},` + extra + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRuleActivation(t *testing.T) {
	for _, activation := range []string{"null", "0", "10", "9007199254740993"} {
		c := ruleConfig(t, fmt.Sprintf(`"wbftRules":{"consensusRules":{"rejectNumberJump":%s}}`, activation))
		for _, at := range []uint64{0, 9, 10, 11, 9007199254740992, 9007199254740993} {
			want := activation != "null" && (activation == "0" || activation == "10" && at >= 10 || activation == "9007199254740993" && at >= 9007199254740993)
			if c.Rules(RejectNumberJump, HeightFromUint64(at)) != want {
				t.Fatalf("activation %s at %d", activation, at)
			}
		}
		copy := c.RuleActivations()
		copy[RejectNumberJump] = "1"
		if h, ok := c.RuleActivation(RejectNumberJump); ok && h.String() != activation {
			t.Fatal("caller changed immutable configuration")
		}
	}
	if ruleConfig(t, `"chainId":1`).Rules(RejectNumberJump, HeightFromUint64(100)) {
		t.Fatal("missing rule enabled")
	}
	for _, value := range []string{`-1`, `"1"`, `true`, `1.5`, `1e2`} {
		if _, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"rejectNumberJump":` + value + `}}}`)); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

func TestMinimalBitmapRuleConfiguration(t *testing.T) {
	c := ruleConfig(t, `"wbftRules":{"consensusRules":{"minimalSealerBitmap":10,"rejectNumberJump":20}}`)
	for _, at := range []uint64{0, 9, 10, 19, 20, 21} {
		if c.Rules(MinimalSealerBitmap, HeightFromUint64(at)) != (at >= 10) || c.Rules(RejectNumberJump, HeightFromUint64(at)) != (at >= 20) {
			t.Fatalf("independent activation at %d", at)
		}
	}
	copy := c.RuleActivations()
	copy[MinimalSealerBitmap] = "0"
	if at, ok := c.RuleActivation(MinimalSealerBitmap); !ok || at.String() != "10" {
		t.Fatal("caller changed activation")
	}
	if ruleConfig(t, `"wbftRules":{"consensusRules":{"minimalSealerBitmap":null}}`).Rules(MinimalSealerBitmap, HeightFromUint64(20)) {
		t.Fatal("null activation enabled")
	}
	for _, value := range []string{`-1`, `"1"`, `true`, `1.5`, `1e2`} {
		_, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"minimalSealerBitmap":` + value + `}}}`))
		if err == nil {
			t.Fatalf("invalid activation accepted: %s", value)
		}
	}
	a := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3))
	full := ruleConfig(t, fmt.Sprintf(`"wbftRules":{"consensusRules":{"minimalSealerBitmap":%s}}`, a.String()))
	for _, delta := range []int64{-1, 0, 1} {
		at := MustHeightFromBig(new(big.Int).Add(new(big.Int).Set(a), big.NewInt(delta)))
		if full.Rules(MinimalSealerBitmap, at) != (delta >= 0) {
			t.Fatalf("full-height activation at %s", at)
		}
	}
	if c.RulesDigest() == ruleConfig(t, `"wbftRules":{"consensusRules":{"minimalSealerBitmap":11,"rejectNumberJump":20}}`).RulesDigest() {
		t.Fatal("activation missing from digest")
	}
}

func TestRulesDigest(t *testing.T) {
	a := ruleConfig(t, `"transitions":[],"wbftRules":{"consensusRules":{"rejectNumberJump":100},"govRules":{"x":9007199254740993,"y":1.00}}`)
	b := ruleConfig(t, `"wbftRules":{"govRules":{"y":1e0,"x":9007199254740993},"consensusRules":{"rejectNumberJump":100}},"transitions":[],"chainId":99`)
	if a.RulesDigest() == (Hash{}) || a.RulesDigest() != b.RulesDigest() {
		t.Fatal("digest depends on key order, whitespace, numeric spelling or unrelated fields")
	}
	for _, extra := range []string{
		`"transitions":[],"wbftRules":{"consensusRules":{"rejectNumberJump":101},"govRules":{"x":9007199254740993,"y":1}}`,
		`"transitions":[],"wbftRules":{"consensusRules":{"rejectNumberJump":100},"govRules":{"x":9007199254740992,"y":1}}`,
		`"transitions":[{"block":10,"epochLength":200}],"wbftRules":{"consensusRules":{"rejectNumberJump":100},"govRules":{"x":9007199254740993,"y":1}}`,
	} {
		if a.RulesDigest() == ruleConfig(t, extra).RulesDigest() {
			t.Fatal("changed chain rules did not change digest")
		}
	}
	for _, pair := range [][2]string{{"100", "1e2"}, {"0.0100", "1e-2"}, {"-0", "0"}, {"-12.00", "-12"}, {"123e+200", "1230e199"}} {
		a := ruleConfig(t, `"wbftRules":{"govRules":{"x":`+pair[0]+`}}`)
		b := ruleConfig(t, `"wbftRules":{"govRules":{"x":`+pair[1]+`}}`)
		if a.RulesDigest() != b.RulesDigest() {
			t.Fatal(strings.Join(pair[:], " != "))
		}
	}
}

func TestStableCandidateRuleConfiguration(t *testing.T) {
	c := ruleConfig(t, `"wbftRules":{"consensusRules":{"stableCandidateSort":10,"minimalSealerBitmap":20,"rejectNumberJump":30}}`)
	for _, at := range []uint64{0, 9, 10, 19, 20, 29, 30, 31} {
		h := HeightFromUint64(at)
		if c.Rules(StableCandidateSort, h) != (at >= 10) || c.Rules(MinimalSealerBitmap, h) != (at >= 20) || c.Rules(RejectNumberJump, h) != (at >= 30) {
			t.Fatalf("independent activation at %d", at)
		}
	}
	copied := c.RuleActivations()
	copied[StableCandidateSort] = "0"
	if at, ok := c.RuleActivation(StableCandidateSort); !ok || at.String() != "10" {
		t.Fatal("caller changed stable ordering activation")
	}
	for _, extra := range []string{`"chainId":1`, `"wbftRules":{"consensusRules":{"stableCandidateSort":null}}`} {
		if ruleConfig(t, extra).Rules(StableCandidateSort, HeightFromUint64(100)) {
			t.Fatal("missing or null stable ordering enabled")
		}
	}
	for _, value := range []string{`-1`, `"1"`, `true`, `1.5`, `1e2`} {
		if _, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"stableCandidateSort":` + value + `}}}`)); err == nil {
			t.Fatal("invalid stable ordering activation accepted", value)
		}
	}
	activation := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3))
	full := ruleConfig(t, fmt.Sprintf(`"wbftRules":{"consensusRules":{"stableCandidateSort":%s}}`, activation.String()))
	for _, delta := range []int64{-1, 0, 1} {
		at := MustHeightFromBig(new(big.Int).Add(new(big.Int).Set(activation), big.NewInt(delta)))
		if full.Rules(StableCandidateSort, at) != (delta >= 0) {
			t.Fatal("stable ordering activation truncated", at)
		}
	}
	if c.RulesDigest() == ruleConfig(t, `"wbftRules":{"consensusRules":{"stableCandidateSort":11,"minimalSealerBitmap":20,"rejectNumberJump":30}}`).RulesDigest() {
		t.Fatal("stable ordering activation missing from digest")
	}
}

func TestFirstProposerBoundRuleConfiguration(t *testing.T) {
	c := ruleConfig(t, `"wbftRules":{"consensusRules":{"firstProposerDiligenceCap":10,"stableCandidateSort":20,"minimalSealerBitmap":30,"rejectNumberJump":40}}`)
	for _, at := range []uint64{0, 9, 10, 19, 20, 29, 30, 39, 40, 41} {
		h := HeightFromUint64(at)
		if c.Rules(FirstProposerDiligenceCap, h) != (at >= 10) || c.Rules(StableCandidateSort, h) != (at >= 20) || c.Rules(MinimalSealerBitmap, h) != (at >= 30) || c.Rules(RejectNumberJump, h) != (at >= 40) {
			t.Fatal("independent activation", at)
		}
	}
	copied := c.RuleActivations()
	copied[FirstProposerDiligenceCap] = "0"
	if h, ok := c.RuleActivation(FirstProposerDiligenceCap); !ok || h.String() != "10" {
		t.Fatal("activation was mutated")
	}
	for _, extra := range []string{`"chainId":1`, `"wbftRules":{"consensusRules":{"firstProposerDiligenceCap":null}}`} {
		if ruleConfig(t, extra).Rules(FirstProposerDiligenceCap, HeightFromUint64(100)) {
			t.Fatal("missing or null activation enabled")
		}
	}
	for _, value := range []string{`-1`, `"1"`, `true`, `1.5`, `1e2`} {
		if _, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"firstProposerDiligenceCap":` + value + `}}}`)); err == nil {
			t.Fatal("invalid activation accepted", value)
		}
	}
	activation := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3))
	full := ruleConfig(t, fmt.Sprintf(`"wbftRules":{"consensusRules":{"firstProposerDiligenceCap":%s}}`, activation.String()))
	for _, delta := range []int64{-1, 0, 1} {
		h := MustHeightFromBig(new(big.Int).Add(new(big.Int).Set(activation), big.NewInt(delta)))
		if full.Rules(FirstProposerDiligenceCap, h) != (delta >= 0) {
			t.Fatal("activation height truncated", h)
		}
	}
	if c.RulesDigest() == ruleConfig(t, `"wbftRules":{"consensusRules":{"firstProposerDiligenceCap":11,"stableCandidateSort":20,"minimalSealerBitmap":30,"rejectNumberJump":40}}`).RulesDigest() {
		t.Fatal("activation omitted from digest")
	}
}

func TestCommittedEpochRuleConfiguration(t *testing.T) {
	c := ruleConfig(t, `"wbftRules":{"consensusRules":{"committedEpochDiligence":10,"stableCandidateSort":20,"minimalSealerBitmap":30,"rejectNumberJump":40}}`)
	for _, at := range []uint64{0, 9, 10, 19, 20, 29, 30, 39, 40, 41} {
		h := HeightFromUint64(at)
		if c.Rules(CommittedEpochDiligence, h) != (at >= 10) || c.Rules(StableCandidateSort, h) != (at >= 20) || c.Rules(MinimalSealerBitmap, h) != (at >= 30) || c.Rules(RejectNumberJump, h) != (at >= 40) {
			t.Fatal("independent activation", at)
		}
	}
	copied := c.RuleActivations()
	copied[CommittedEpochDiligence] = "0"
	if h, ok := c.RuleActivation(CommittedEpochDiligence); !ok || h.String() != "10" {
		t.Fatal("activation was mutated")
	}
	for _, extra := range []string{`"chainId":1`, `"wbftRules":{"consensusRules":{"committedEpochDiligence":null}}`} {
		if ruleConfig(t, extra).Rules(CommittedEpochDiligence, HeightFromUint64(100)) {
			t.Fatal("missing or null activation enabled")
		}
	}
	for _, value := range []string{`-1`, `"1"`, `true`, `1.5`, `1e2`} {
		if _, err := ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"committedEpochDiligence":` + value + `}}}`)); err == nil {
			t.Fatal("invalid activation accepted", value)
		}
	}
	activation := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3))
	full := ruleConfig(t, fmt.Sprintf(`"wbftRules":{"consensusRules":{"committedEpochDiligence":%s}}`, activation.String()))
	for _, delta := range []int64{-1, 0, 1} {
		h := MustHeightFromBig(new(big.Int).Add(new(big.Int).Set(activation), big.NewInt(delta)))
		if full.Rules(CommittedEpochDiligence, h) != (delta >= 0) {
			t.Fatal("activation height truncated", h)
		}
	}
	if c.RulesDigest() == ruleConfig(t, `"wbftRules":{"consensusRules":{"committedEpochDiligence":11,"stableCandidateSort":20,"minimalSealerBitmap":30,"rejectNumberJump":40}}`).RulesDigest() {
		t.Fatal("activation omitted from digest")
	}
}
