package journal

import (
	"fmt"

	"github.com/0xmhha/wbft/types"
)

// CheckedProposerPolicyProfile identifies the effective policy derivation
// recorded by nodes. An absent profile preserves legacy configuration parsing.
const CheckedProposerPolicyProfile = "checked_v1"

// Configuration derives the recorded configuration without rewriting its JSON.
// Unknown policy profiles cannot silently select the current node behavior.
func (o CoreOptions) Configuration() (*types.Config, error) {
	if err := o.ValidateRuntimeProfiles(); err != nil {
		return nil, err
	}
	cfg, err := types.ParseChainConfig(o.ChainConfig)
	if err != nil {
		return nil, err
	}
	if _, err := o.RetryOptions(cfg); err != nil {
		return nil, err
	}
	if o.Observation != nil && (cfg.ChainID == nil || cfg.ChainID.String() != o.Observation.ChainID) {
		return nil, fmt.Errorf("journal: observation chain ID differs from chain configuration")
	}
	switch o.ProposerPolicyProfile {
	case "":
		return cfg, nil
	case CheckedProposerPolicyProfile:
		return cfg.CheckedProposerPolicy()
	default:
		return nil, fmt.Errorf("journal: unsupported proposer policy profile %q", o.ProposerPolicyProfile)
	}
}
