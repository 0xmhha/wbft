package consensus

import (
	"encoding/hex"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// Verified is a decoded consensus message whose signatures have been
// recovered: Source is the signer of Msg, RoundChangeSources and
// PrepareSources are the signers of Msg.RoundChanges and Msg.Prepares in
// order.
type Verified struct {
	Msg                *codec.Message
	Source             types.Address
	RoundChangeSources []types.Address
	PrepareSources     []types.Address
}

// Recover decodes payload and recovers the signer of the message and of
// every justification member in the order of WBFT-SM-017. isMember is asked
// for each signer with the view of the signed payload; a nil isMember accepts
// every signer. It fails at the first decoding, recovery or membership
// failure.
//
// Spec: WBFT-SM-015, WBFT-SM-017
func Recover(code codec.Code, payload []byte, isMember func(types.Address, types.View) bool) (*Verified, error) {
	m, err := codec.DecodeMessage(code, payload)
	if err != nil {
		return nil, err
	}
	return RecoverDecoded(m, isMember)
}

// RecoverDecoded is Recover for an already decoded message.
func RecoverDecoded(m *codec.Message, isMember func(types.Address, types.View) bool) (*Verified, error) {
	v := &Verified{Msg: m}
	one := func(x *codec.Message) (types.Address, error) {
		payload, err := codec.SigningPayload(x, false, nil)
		if err != nil {
			return types.Address{}, err
		}
		member := func(a types.Address) bool { return isMember == nil || isMember(a, x.View) }
		return ecdsa.CheckValidatorSignature(member, payload, x.Signature)
	}
	var err error
	if v.Source, err = one(m); err != nil {
		return nil, err
	}
	switch m.Code {
	case codec.CodeRoundChange:
		for _, p := range m.Prepares {
			a, err := one(p)
			if err != nil {
				return nil, err
			}
			v.PrepareSources = append(v.PrepareSources, a)
		}
	case codec.CodePreprepare:
		for _, rc := range m.RoundChanges {
			a, err := one(rc)
			if err != nil {
				return nil, err
			}
			v.RoundChangeSources = append(v.RoundChangeSources, a)
		}
		for _, p := range m.Prepares {
			a, err := one(p)
			if err != nil {
				return nil, err
			}
			v.PrepareSources = append(v.PrepareSources, a)
		}
	}
	return v, nil
}

// Encode returns rlp_encode(v.Msg).
func (v *Verified) Encode() ([]byte, error) { return codec.EncodeMessage(v.Msg) }

// prepares returns the justification PREPAREs of v with their sources.
func (v *Verified) prepares() []*Verified {
	out := make([]*Verified, len(v.Msg.Prepares))
	for i, p := range v.Msg.Prepares {
		out[i] = &Verified{Msg: p, Source: v.PrepareSources[i]}
	}
	return out
}

// roundChanges returns the justification ROUND-CHANGE payloads of a
// PRE-PREPARE with their sources.
func (v *Verified) roundChanges() []*Verified {
	out := make([]*Verified, len(v.Msg.RoundChanges))
	for i, rc := range v.Msg.RoundChanges {
		out[i] = &Verified{Msg: rc, Source: v.RoundChangeSources[i]}
	}
	return out
}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }
func hexHash(h types.Hash) string    { return "0x" + hex.EncodeToString(h[:]) }
func hexBytes(b []byte) string       { return "0x" + hex.EncodeToString(b) }
