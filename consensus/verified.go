package consensus

import (
	"encoding/hex"
	"errors"

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
	v, _, err := RecoverWithFailure(code, payload, isMember)
	return v, err
}

// RecoverWithFailure performs Recover's complete checks and separately names
// the first failing phase. The classification grants no cache or signer
// authority. Existing error values and the order of checks are preserved.
func RecoverWithFailure(code codec.Code, payload []byte, isMember func(types.Address, types.View) bool) (*Verified, RecoveryFailure, error) {
	m, err := codec.DecodeMessage(code, payload)
	if err != nil {
		return nil, RecoveryDecode, err
	}
	return RecoverDecodedWithFailure(m, isMember)
}

// RecoverDecoded is Recover for an already decoded message.
func RecoverDecoded(m *codec.Message, isMember func(types.Address, types.View) bool) (*Verified, error) {
	v, _, err := RecoverDecodedWithFailure(m, isMember)
	return v, err
}

// RecoverDecodedWithFailure is RecoverWithFailure for an already decoded
// message. Membership remains a check of the caller's current authority
// context; a valid cryptographic signature alone does not satisfy it.
func RecoverDecodedWithFailure(m *codec.Message, isMember func(types.Address, types.View) bool) (*Verified, RecoveryFailure, error) {
	v := &Verified{Msg: m}
	one := func(x *codec.Message) (types.Address, RecoveryFailure, error) {
		payload, err := codec.SigningPayload(x, false, nil)
		if err != nil {
			return types.Address{}, RecoveryEncoding, err
		}
		member := func(a types.Address) bool { return isMember == nil || isMember(a, x.View) }
		source, err := ecdsa.CheckValidatorSignature(member, payload, x.Signature)
		if err != nil {
			if errors.Is(err, ecdsa.ErrUnauthorizedAddress) {
				return source, RecoveryMembership, err
			}
			return source, RecoverySignature, err
		}
		return source, RecoverySucceeded, nil
	}
	var err error
	var failure RecoveryFailure
	if v.Source, failure, err = one(m); err != nil {
		return nil, failure, err
	}
	switch m.Code {
	case codec.CodeRoundChange:
		for _, p := range m.Prepares {
			a, failure, err := one(p)
			if err != nil {
				return nil, failure, err
			}
			v.PrepareSources = append(v.PrepareSources, a)
		}
	case codec.CodePreprepare:
		for _, rc := range m.RoundChanges {
			a, failure, err := one(rc)
			if err != nil {
				return nil, failure, err
			}
			v.RoundChangeSources = append(v.RoundChangeSources, a)
		}
		for _, p := range m.Prepares {
			a, failure, err := one(p)
			if err != nil {
				return nil, failure, err
			}
			v.PrepareSources = append(v.PrepareSources, a)
		}
	}
	return v, RecoverySucceeded, nil
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
