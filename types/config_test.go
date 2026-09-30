package types

import "testing"

func TestCheckConsensusRules(t *testing.T) {
	for _, c := range []struct {
		cfg string
		ok  bool
	}{
		{`{"chainId":1}`, true},
		{`{"wbftRules":null}`, true},
		{`{"wbftRules":{"consensusRules":{},"featureRules":null,"govRules":{"x":1}}}`, true},
		{`{"wbftRules":{"consensusRules":{"rejectNumberJump":100}}}`, false},
		{`{"wbftRules":{"featureRules":{"anything":null}}}`, false},
		{`{"wbftRules":{"consensusRules":[1]}}`, false},
	} {
		if err := CheckConsensusRules([]byte(c.cfg)); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.cfg, err, c.ok)
		}
	}
}
