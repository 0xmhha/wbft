package codec

import (
	"bytes"
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

const roundChangeDomainTag = "wbft/round-change-domain"

// SigningPayloadWithDomain preserves legacy bytes unless the message itself
// is a round change at or after the context's full activation height. It does
// not select a context from the message, an outer message or the current head.
func SigningPayloadWithDomain(message *Message, domain *types.RoundChangeDomain) ([]byte, error) {
	if message == nil {
		return nil, ErrUnknownCode
	}
	if err := domain.Validate(); err != nil {
		return nil, err
	}
	legacy, err := SigningPayload(message, false, nil)
	if err != nil || message.Code != CodeRoundChange || !domain.Active(message.View.Sequence) {
		return legacy, err
	}
	// The normalized legacy payload is a byte string, not an embedded RLP list.
	return rlp.Encode([]any{roundChangeDomainTag, domain.Version(), domain.ChainID(), domain.GenesisHash(), legacy})
}

type roundChangeDomainRLP struct {
	Version    uint64
	ChainID    *big.Int
	Genesis    types.Hash
	Activation *big.Int
}

// EncodeRoundChangeDomain encodes the explicit public profile. Nil has no
// declaration bytes, preserving legacy optional-field encodings.
func EncodeRoundChangeDomain(domain *types.RoundChangeDomain) ([]byte, error) {
	if err := domain.Validate(); err != nil {
		return nil, err
	}
	if domain == nil {
		return nil, nil
	}
	return rlp.Encode(roundChangeDomainRLP{domain.Version(), domain.ChainID(), domain.GenesisHash(), domain.Activation().Big()})
}

// DecodeRoundChangeDomain accepts only the canonical supported declaration.
// A decoded declaration is a claim, not independent genesis authentication.
func DecodeRoundChangeDomain(raw []byte) (*types.RoundChangeDomain, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var wire roundChangeDomainRLP
	if rlp.DecodeStrict(raw, &wire) != nil {
		return nil, types.ErrRoundChangeDomain
	}
	if wire.Version != types.RoundChangeDomainVersion {
		return nil, types.ErrRoundChangeDomainVersion
	}
	activation, err := types.HeightFromBig(wire.Activation)
	if err != nil {
		return nil, types.ErrRoundChangeDomain
	}
	domain, err := types.NewRoundChangeDomain(wire.ChainID, wire.Genesis, activation)
	if err != nil {
		return nil, err
	}
	canonical, err := EncodeRoundChangeDomain(domain)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, types.ErrRoundChangeDomain
	}
	return domain, nil
}
