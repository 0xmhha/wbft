package codec

import (
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

type consensusEnvelope struct {
	Version     uint64
	Legacy      rlp.RawValue
	Proofs      rlp.RawValue
	Observation rlp.RawValue
}

// consensusParts supplies a format view only. Admission and observation
// limits remain the verifier's explicit responsibility.
func consensusParts(raw []byte) (*types.WBFTExtra, *consensusEnvelope, error) {
	x, legacyErr := DecodeExtraBytes(raw)
	if legacyErr == nil {
		return x, nil, nil
	}
	var envelope consensusEnvelope
	if rlp.DecodeStrict(raw, &envelope) != nil || envelope.Version != 2 {
		return nil, nil, legacyErr
	}
	for _, item := range []rlp.RawValue{envelope.Proofs, envelope.Observation} {
		if _, rest, err := rlp.SplitList(item); err != nil || len(rest) != 0 {
			return nil, nil, legacyErr
		}
	}
	x, err := DecodeExtraBytes(envelope.Legacy)
	if err != nil {
		return nil, nil, legacyErr
	}
	return x, &envelope, nil
}

// DecodeConsensusExtra returns an owned nested legacy view for consensus
// primitives. It does not validate or enable an observation policy. The strict
// legacy DecodeExtra API remains unchanged.
func DecodeConsensusExtra(h *types.Header) (*types.WBFTExtra, error) {
	x, _, err := consensusParts(h.Extra)
	return x, err
}

// SetConsensusExtra replaces only the nested legacy fields and preserves the
// outer proof and observation encodings byte for byte. It cannot wrap a legacy
// header or select a new observation policy.
func SetConsensusExtra(h *types.Header, x *types.WBFTExtra) error {
	_, envelope, err := consensusParts(h.Extra)
	if err != nil {
		return err
	}
	encoded, err := encodeConsensusExtra(x, envelope)
	if err != nil {
		return err
	}
	h.Extra = encoded
	return nil
}

func encodeConsensusExtra(x *types.WBFTExtra, envelope *consensusEnvelope) ([]byte, error) {
	raw, err := EncodeExtra(x)
	if err != nil {
		return nil, err
	}
	if envelope == nil {
		return raw, nil
	}
	envelope.Legacy = raw
	return rlp.Encode(envelope)
}
