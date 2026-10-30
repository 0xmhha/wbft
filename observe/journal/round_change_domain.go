package journal

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/types"
)

// ErrDomainSourceUnsupported separates future declarations from malformed
// supported data. Neither result grants a chain identity or replay authority.
var ErrDomainSourceUnsupported = errors.New("journal: unsupported round-change domain source")

// DomainOptions checks an explicit portable description against the common
// rule. Identity binding to a segment's CID and genesis is a separate check.
func (o CoreOptions) DomainOptions(config *types.Config) (*types.RoundChangeDomain, error) {
	domain, err := codec.DecodeRoundChangeDomain(o.DomainBytes)
	if err != nil {
		if errors.Is(err, types.ErrRoundChangeDomainVersion) {
			return nil, fmt.Errorf("%w: %w", ErrDomainSourceUnsupported, err)
		}
		return nil, err
	}
	if err := types.ValidateRoundChangeDomain(config, domain); err != nil {
		return nil, err
	}
	return domain, nil
}

// matchSignerDomain binds the public signer lifetime to its recorded owner.
// Signature equality alone cannot bind pre-activation or non-RC messages.
func matchSignerDomain(source privval.Source, declared []byte) error {
	if source.Version != privval.SourceVersion && source.Version != privval.DomainSourceVersion {
		return ErrSignerSourceUnsupported
	}
	if source.Version == privval.DomainSourceVersion {
		if err := privval.ValidateSource(source); err != nil {
			if errors.Is(err, types.ErrRoundChangeDomainVersion) {
				return ErrSignerSourceUnsupported
			}
			return err
		}
		// ValidateSource permits omission only with the explicit unavailable
		// marker. An unmarked supported source remains malformed.
		if len(source.DomainBytes) == 0 {
			return ErrSignerSourceUnsupported
		}
	}
	version := privval.SourceVersion
	if len(declared) != 0 {
		version = privval.DomainSourceVersion
	}
	if source.Version != version || !bytes.Equal(source.DomainBytes, declared) {
		return types.ErrRoundChangeDomain
	}
	return nil
}

// ValidateDomainIdentity binds a description to the same segment identity.
// Recorded declarations remain claims, not independent genesis authentication.
func (id Identity) ValidateDomainIdentity() error {
	if len(id.Core.ChainConfig) == 0 && len(id.Core.DomainBytes) == 0 {
		return nil
	}
	config, err := types.ParseChainConfig(id.Core.ChainConfig)
	if err != nil {
		// Legacy headers can carry opaque or absent configuration. A selected
		// description cannot gain that legacy exemption.
		if len(id.Core.DomainBytes) == 0 {
			return nil
		}
		return err
	}
	domain, err := id.Core.DomainOptions(config)
	if err != nil || domain == nil {
		return err
	}
	if id.ChainID == nil || id.ChainID.Cmp(domain.ChainID()) != 0 || id.GenesisHash != domain.GenesisHash() {
		return types.ErrRoundChangeDomain
	}
	return nil
}
