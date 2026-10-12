package types

import (
	"fmt"
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
