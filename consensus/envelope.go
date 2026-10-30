package consensus

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// OuterSigner identifies a frame's recovered outer signer. It establishes
// neither validator membership nor the validity of attached signatures, seals
// or proposals. It cannot be used in place of Verified.
type OuterSigner struct {
	Code   codec.Code
	View   types.View
	Source types.Address
}

// RecoverOuter recovers only the outer ECDSA signature using the codec's
// signed-field normalization. It does not check validator membership and does
// not return a Verified message. Consensus processing must still use Recover
// with the appropriate validator set before observing, counting or relaying a
// message. This helper does not change the receive path or admission policy.
func RecoverOuter(code codec.Code, payload []byte) (*OuterSigner, error) {
	return RecoverOuterWithDomain(code, payload, nil)
}

// RecoverOuterWithDomain recovers an outer signature under an explicit chain
// context. Success does not check membership or authenticate attachments.
func RecoverOuterWithDomain(code codec.Code, payload []byte, domain *types.RoundChangeDomain) (*OuterSigner, error) {
	e, err := codec.DecodeSignedEnvelopeWithDomain(code, payload, domain)
	if err != nil {
		return nil, err
	}
	source, err := ecdsa.RecoverDataSigner(e.SigningPayload, e.Signature)
	if err != nil {
		return nil, err
	}
	return &OuterSigner{Code: code, View: e.View, Source: source}, nil
}
