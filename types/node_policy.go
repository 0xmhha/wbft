package types

import (
	"fmt"
	"math/big"
)

// CheckedProposerPolicy returns an independent effective node configuration.
// An omitted base policy selects RoundRobin; explicit policies in the base
// or a transition must select RoundRobin or Sticky. The source configuration
// and its original rule declarations remain unchanged.
func (c *Config) CheckedProposerPolicy() (*Config, error) {
	if c == nil {
		return nil, &ErrConfig{Field: "config", Reason: "missing"}
	}
	out := *c
	out.base = c.base.copy()
	out.transitions = c.Transitions()
	out.Init = copyInit(c.Init)
	if c.ChainID != nil {
		out.ChainID = new(big.Int).Set(c.ChainID)
	}
	if c.rules != nil {
		out.rules = make(map[RuleName]Height, len(c.rules))
		for name, height := range c.rules { //wbft:unordered independent map copy
			out.rules[name] = height
		}
	}
	if out.base.ProposerPolicy == nil {
		out.base.ProposerPolicy = &ProposerPolicy{ID: RoundRobin}
	}
	check := func(id uint64, field string) error {
		if id != RoundRobin && id != Sticky {
			return &ErrConfig{Field: field, Reason: "must be 0 or 1"}
		}
		return nil
	}
	if err := check(out.base.ProposerPolicy.ID, "anzeon.wbft.proposerPolicy"); err != nil {
		return nil, err
	}
	for i, transition := range out.transitions {
		if transition.WBFT != nil && transition.WBFT.ProposerPolicy != nil {
			if err := check(*transition.WBFT.ProposerPolicy, fmt.Sprintf("transitions[%d].proposerPolicy", i)); err != nil {
				return nil, err
			}
		}
	}
	return &out, nil
}
