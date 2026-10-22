package codec

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
	gethrlp "github.com/ethereum/go-ethereum/rlp"
)

// SignedEnvelope contains only the fields needed to recover an outer signer.
// It is not a decoded consensus message: attachments have not been decoded or
// authenticated, and the signer has not been checked against a validator set.
type SignedEnvelope struct {
	Code           Code
	View           types.View
	Signature      []byte
	SigningPayload []byte
}

// ErrEnvelopeSize reports a payload outside the transport's frame limit.
var ErrEnvelopeSize = errors.New("codec: signed envelope exceeds frame limit")

// DecodeSignedEnvelope decodes the signed outer portion of a consensus frame.
// It uses the same signed-field decoders and signing-payload normalization as
// DecodeMessage, but does not decode attached round changes, prepares or a
// ROUND-CHANGE's prepared block. A PRE-PREPARE's signed proposal is decoded.
//
// Success does not establish that the complete message is valid. Callers must
// still decode and authenticate the complete message before consensus use.
// The payload must fit MaxIstanbulMsgSize. This bound is not a heap or CPU
// bound; proposal decoding and the signing-payload copy can allocate.
func DecodeSignedEnvelope(code Code, payload []byte) (*SignedEnvelope, error) {
	if len(payload) > types.MaxIstanbulMsgSize {
		return nil, ErrEnvelopeSize
	}
	m, err := decodeEnvelopeMessage(code, payload)
	if err != nil {
		switch code {
		case CodePreprepare:
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodePreprepare, err)
		case CodePrepare, CodeCommit:
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodeCommit, err)
		case CodeRoundChange:
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodeRoundChange, err)
		}
		return nil, err
	}
	p, err := SigningPayload(m, false, nil)
	if err != nil {
		return nil, err
	}
	return &SignedEnvelope{Code: code, View: m.View, Signature: m.Signature, SigningPayload: p}, nil
}

func decodeEnvelopeMessage(code Code, payload []byte) (*Message, error) {
	switch code {
	case CodePrepare, CodeCommit:
		return decodeVote(code, payload)
	case CodeRoundChange:
		items, err := envelopeItems(payload, 3)
		if err != nil {
			return nil, err
		}
		s, r := newStream(items[0])
		m := &Message{}
		if err := decodeSignedRoundChange(s, m); err != nil {
			return nil, err
		}
		if r.Len() != 0 {
			return nil, gethrlp.ErrMoreThanOneValue
		}
		return m, nil
	case CodePreprepare:
		items, err := envelopeItems(payload, 2)
		if err != nil {
			return nil, err
		}
		var w signedPreprepareRLP
		if err := rlp.DecodeStrict(items[0], &w); err != nil {
			return nil, err
		}
		return w.message(), nil
	}
	return nil, ErrUnknownCode
}

// envelopeItems borrows at most three top-level items. It does not build an
// unbounded slice when a frame contains more top-level values than expected.
func envelopeItems(payload []byte, want int) ([3][]byte, error) {
	var items [3][]byte
	content, rest, err := rlp.SplitList(payload)
	if err != nil {
		return items, err
	}
	if len(rest) != 0 {
		return items, gethrlp.ErrMoreThanOneValue
	}
	for i := 0; i < want; i++ {
		if len(content) == 0 {
			return items, gethrlp.EOL
		}
		_, _, tail, err := gethrlp.Split(content)
		if err != nil {
			return items, err
		}
		items[i] = content[:len(content)-len(tail)]
		content = tail
	}
	if len(content) != 0 {
		return items, gethrlp.ErrMoreThanOneValue
	}
	return items, nil
}
