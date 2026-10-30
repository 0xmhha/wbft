package types

import (
	"errors"
	"fmt"
	"math/big"
)

// RoundChangeDomainRule selects chain-bound round-change signatures.
const RoundChangeDomainRule RuleName = "roundChangeDomain"

// RoundChangeDomainVersion identifies the chain identity signing envelope.
const RoundChangeDomainVersion uint64 = 1

// ErrRoundChangeDomain reports a missing or inconsistent signing context.
var ErrRoundChangeDomain = errors.New("types: invalid round-change domain")

// ErrRoundChangeDomainVersion distinguishes an unsupported profile version
// from malformed data. It also matches ErrRoundChangeDomain.
var ErrRoundChangeDomainVersion = fmt.Errorf("%w: unsupported version", ErrRoundChangeDomain)

// RoundChangeDomain is an immutable identity and activation schedule. A caller
// must obtain genesis from a trusted source; this value does not authenticate it.
// The zero value is invalid. Nil explicitly selects legacy signing.
type RoundChangeDomain struct {
	version    uint64
	chainID    *big.Int
	genesis    Hash
	activation Height
}

// NewRoundChangeDomain copies the full chain identifier and activation height.
func NewRoundChangeDomain(chainID *big.Int, genesis Hash, activation Height) (*RoundChangeDomain, error) {
	if chainID == nil || chainID.Sign() <= 0 || genesis == (Hash{}) || activation.IsZero() {
		return nil, ErrRoundChangeDomain
	}
	return &RoundChangeDomain{RoundChangeDomainVersion, new(big.Int).Set(chainID), genesis, MustHeightFromBig(activation.Big())}, nil
}

// DomainForConfig derives the configured profile from an already verified
// genesis hash. A disabled rule does not require a genesis witness.
func DomainForConfig(config *Config, genesis Hash) (*RoundChangeDomain, error) {
	if config == nil {
		return nil, nil
	}
	at, configured := config.RuleActivation(RoundChangeDomainRule)
	if !configured {
		return nil, nil
	}
	return NewRoundChangeDomain(config.ChainID, genesis, at)
}

// Validate accepts nil as the explicit legacy profile, never an invalid value.
func (d *RoundChangeDomain) Validate() error {
	if d != nil && (d.version != RoundChangeDomainVersion || d.chainID == nil || d.chainID.Sign() <= 0 || d.genesis == (Hash{}) || d.activation.IsZero()) {
		return ErrRoundChangeDomain
	}
	return nil
}

// ValidateRoundChangeDomain binds a supplied profile to the common chain rule.
// A configured rule requires its context even before the activation height.
func ValidateRoundChangeDomain(config *Config, domain *RoundChangeDomain) error {
	if err := domain.Validate(); err != nil {
		return err
	}
	var at Height
	var configured bool
	if config != nil {
		at, configured = config.RuleActivation(RoundChangeDomainRule)
	}
	if !configured {
		if domain != nil {
			return ErrRoundChangeDomain
		}
		return nil
	}
	if domain == nil || config.ChainID == nil || config.ChainID.Cmp(domain.chainID) != 0 || at.Cmp(domain.activation) != 0 {
		return ErrRoundChangeDomain
	}
	return nil
}

// Version returns zero for the explicit legacy profile.
func (d *RoundChangeDomain) Version() uint64 {
	if d == nil {
		return 0
	}
	return d.version
}

// ChainID returns an independent full identifier, or nil for legacy signing.
func (d *RoundChangeDomain) ChainID() *big.Int {
	if d == nil || d.chainID == nil {
		return nil
	}
	return new(big.Int).Set(d.chainID)
}

// GenesisHash returns the frozen genesis identity.
func (d *RoundChangeDomain) GenesisHash() Hash {
	if d == nil {
		return Hash{}
	}
	return d.genesis
}

// Activation returns the immutable full activation height.
func (d *RoundChangeDomain) Activation() Height {
	if d == nil {
		return Height{}
	}
	return MustHeightFromBig(d.activation.Big())
}

// Active selects the signed message's own sequence, not the receiving head.
func (d *RoundChangeDomain) Active(sequence Height) bool {
	return d != nil && d.Validate() == nil && sequence.Cmp(d.activation) >= 0
}

// Copy returns independent context storage and preserves invalid zero values.
// Callers must still validate a copied context before using it.
func (d *RoundChangeDomain) Copy() *RoundChangeDomain {
	if d == nil {
		return nil
	}
	return &RoundChangeDomain{d.version, d.ChainID(), d.genesis, d.Activation()}
}

// Equal compares identity, version and full activation, including nil.
func (d *RoundChangeDomain) Equal(other *RoundChangeDomain) bool {
	if d == nil || other == nil {
		return d == nil && other == nil
	}
	if d.Validate() != nil || other.Validate() != nil {
		return false
	}
	return d.version == other.version && d.chainID.Cmp(other.chainID) == 0 && d.genesis == other.genesis && d.activation.Cmp(other.activation) == 0
}
