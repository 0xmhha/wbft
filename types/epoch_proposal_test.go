package types

import (
	"fmt"
	"testing"
)

func TestEpochProposalRulePrerequisites(t *testing.T) {
	for _, entry := range []struct {
		rules string
		ok    bool
	}{
		{`"epochInfoInProposal":null`, true},
		{`"epochInfoInProposal":0`, false},
		{`"epochInfoInProposal":4,"committedEpochDiligence":null`, false},
		{`"epochInfoInProposal":4,"committedEpochDiligence":5`, false},
		{`"epochInfoInProposal":4,"committedEpochDiligence":4`, true},
		{`"epochInfoInProposal":4,"committedEpochDiligence":0`, true},
		{`"epochInfoInProposal":-1,"committedEpochDiligence":0`, false},
		{`"epochInfoInProposal":0.0,"committedEpochDiligence":0`, false},
		{`"epochInfoInProposal":"0","committedEpochDiligence":0`, false},
		{`"epochInfoInProposal":true,"committedEpochDiligence":0`, false},
		{`"epochInfoInProposal":1208925819614629174706176,"committedEpochDiligence":0`, true},
	} {
		raw := []byte(fmt.Sprintf(`{"anzeon":{"wbft":{"epochLength":4,"proposerPolicy":0}},"wbftRules":{"consensusRules":{%s}}}`, entry.rules))
		cfg, err := ParseChainConfig(raw)
		if (err == nil) != entry.ok {
			t.Fatalf("%s: %v", entry.rules, err)
		}
		if (CheckConsensusRules(raw) == nil) != entry.ok {
			t.Fatalf("rules-only validation disagrees: %s", entry.rules)
		}
		if cfg != nil {
			if at, ok := cfg.RuleActivation(EpochInfoInProposal); ok {
				if !cfg.Rules(EpochInfoInProposal, at) {
					t.Fatal("activation boundary ignored")
				}
				if before, ok := at.Sub(HeightFromUint64(1)); ok && cfg.Rules(EpochInfoInProposal, before) {
					t.Fatal("early activation")
				}
			}
		}
	}
}
