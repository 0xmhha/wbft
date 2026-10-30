package privval

import (
	"bytes"
	"math/big"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

func sourceDomain(s Source) (*types.RoundChangeDomain, error) {
	if s.Version == SourceVersion && len(s.DomainBytes) == 0 {
		return nil, nil
	}
	if s.Version != DomainSourceVersion || len(s.DomainBytes) == 0 {
		return nil, ErrSource
	}
	return codec.DecodeRoundChangeDomain(s.DomainBytes)
}

// The independent observer decodes its own envelope and uses the existing
// independent public-state parser, not runtime decodeState/commit helpers.
type sourceDomainStateRLP struct {
	Version    uint64
	ChainID    *big.Int
	Genesis    types.Hash
	Activation *big.Int
	Self       types.Address
	State      []byte
}

func decodeSourceState(s Source, raw []byte, limit uint64) (fileState, error) {
	if s.Version == SourceVersion {
		return decodeSourcePublicState(raw, limit, s.Address)
	}
	var empty fileState
	domain, err := sourceDomain(s)
	if err != nil {
		return empty, err
	}
	if len(raw) < 2 || raw[0] != 2 {
		return empty, ErrSource
	}
	var wire sourceDomainStateRLP
	if rlp.DecodeStrict(raw[1:], &wire) != nil || wire.Version != 1 || wire.ChainID == nil || wire.Activation == nil || wire.ChainID.Cmp(domain.ChainID()) != 0 || wire.Genesis != domain.GenesisHash() || wire.Activation.Cmp(domain.Activation().Big()) != 0 || wire.Self != s.Address {
		return empty, ErrSource
	}
	encoded, err := rlp.Encode(wire)
	if err != nil || !bytes.Equal(encoded, raw[1:]) {
		return empty, ErrSource
	}
	return decodeSourcePublicState(wire.State, limit, s.Address)
}

func encodeSourceState(s Source, st fileState) ([]byte, error) {
	legacy, err := encodeSourcePublicState(st)
	if err != nil || s.Version == SourceVersion {
		return legacy, err
	}
	domain, err := sourceDomain(s)
	if err != nil {
		return nil, err
	}
	body, err := rlp.Encode(sourceDomainStateRLP{1, domain.ChainID(), domain.GenesisHash(), domain.Activation().Big(), s.Address, legacy})
	if err != nil {
		return nil, err
	}
	return append([]byte{2}, body...), nil
}
