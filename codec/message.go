// Copyright 2025 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// The encoders and decoders of this file follow the RLP methods of the
// message types in consensus/wbft/messages of go-stablenet (commit
// 740526d03), which are derived from quorum/consensus/istanbul/qbft/types.
// The decoding steps of ROUND-CHANGE are kept in the same order.

package codec

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
	gethrlp "github.com/ethereum/go-ethereum/rlp"
)

// Code is the devp2p message code of a consensus message.
type Code uint64

// Message codes.
//
// Spec: WBFT-PARAM-001, WBFT-PARAM-002
const (
	CodeIstanbul    Code = 0x11 // legacy code; never decoded as a consensus message
	CodePreprepare  Code = 0x12
	CodePrepare     Code = 0x13
	CodeCommit      Code = 0x14
	CodeRoundChange Code = 0x15
)

// Decoding errors, one per code as the reference reports them. They are
// informative: tests and vectors compare only that decoding failed.
var (
	ErrUnknownCode             = errors.New("invalid message code")
	ErrFailedDecodePreprepare  = errors.New("failed to decode PRE-PREPARE message")
	ErrFailedDecodeCommit      = errors.New("failed to decode COMMIT message") // also PREPARE, as in the reference
	ErrFailedDecodeRoundChange = errors.New("failed to decode ROUND-CHANGE message")
)

// Message is a decoded consensus message. Which fields are used depends on
// Code:
//
//   - PREPARE, COMMIT: View, Digest, Seal, Signature.
//   - ROUND-CHANGE: View, PreparedRound, PreparedDigest, Signature,
//     PreparedBlock, Prepares. An embedded signed round-change payload (in a
//     PRE-PREPARE justification) has no PreparedBlock and no Prepares.
//   - PRE-PREPARE: View, Proposal, Signature, RoundChanges, Prepares.
type Message struct {
	Code      Code
	View      types.View
	Digest    types.Hash
	Seal      []byte
	Proposal  *types.Block
	Signature []byte

	// PreparedRound is nil when the prepared list is empty.
	PreparedRound  *types.Round
	PreparedDigest types.Hash
	PreparedBlock  *types.Block

	RoundChanges []*Message // PRE-PREPARE justification: signed round-change payloads
	Prepares     []*Message // PRE-PREPARE and ROUND-CHANGE justification
}

// DecodeMessage decodes the devp2p payload of a message with the given code.
// A code outside 0x12 .. 0x15 is not decoded.
//
// Spec: WBFT-MSG-001, WBFT-MSG-004
func DecodeMessage(code Code, payload []byte) (*Message, error) {
	switch code {
	case CodePreprepare:
		m, err := decodePreprepare(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodePreprepare, err)
		}
		return m, nil
	case CodePrepare, CodeCommit:
		m, err := decodeVote(code, payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodeCommit, err)
		}
		return m, nil
	case CodeRoundChange:
		m, err := decodeRoundChange(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFailedDecodeRoundChange, err)
		}
		return m, nil
	}
	return nil, ErrUnknownCode
}

// EncodeMessage returns the devp2p payload of m. For a message returned by
// DecodeMessage it is the received payload, except for the ROUND-CHANGE
// re-encodings of A-03 section 7.
//
// Spec: WBFT-MSG-010, WBFT-MSG-020, WBFT-MSG-030, WBFT-MSG-031, WBFT-MSG-040
func EncodeMessage(m *Message) ([]byte, error) {
	switch m.Code {
	case CodePrepare, CodeCommit:
		return rlp.Encode([]any{votePayload(m), m.Signature})
	case CodeRoundChange:
		return encodeRoundChange(m)
	case CodePreprepare:
		return encodePreprepare(m)
	}
	return nil, ErrUnknownCode
}

// ErrChainIDPayload is returned by SigningPayload when asked for the payload
// with a chain id; networks mixed with the reference never use it.
var ErrChainIDPayload = errors.New("codec: signing payload with chain id is not available")

// SigningPayload returns message_signing_payload(m) = rlp([code,
// signed_fields]) computed from the decoded fields. withChainID selects the
// variant with a chain id, which is not available and must be false.
//
// Spec: WBFT-MSG-002, WBFT-MSG-003, WBFT-ENC-090
func SigningPayload(m *Message, withChainID bool, chainID *big.Int) ([]byte, error) {
	if withChainID {
		return nil, ErrChainIDPayload
	}
	_ = chainID
	switch m.Code {
	case CodePrepare, CodeCommit:
		return rlp.Encode([]any{uint64(m.Code), votePayload(m)})
	case CodeRoundChange:
		p, err := roundChangePayload(m)
		if err != nil {
			return nil, err
		}
		return rlp.Encode([]any{uint64(m.Code), rlp.RawValue(p)})
	case CodePreprepare:
		prop, err := encodeProposal(m.Proposal)
		if err != nil {
			return nil, err
		}
		return rlp.Encode([]any{uint64(m.Code), []any{m.View.Sequence.Big(), m.View.Round.Big(), rlp.RawValue(prop)}})
	}
	return nil, ErrUnknownCode
}

// EncodeSignedRoundChange returns the encoding [rc_payload, signature] of a
// round-change payload, as it appears in a PRE-PREPARE justification.
//
// Spec: WBFT-MSG-034
func EncodeSignedRoundChange(m *Message) ([]byte, error) {
	p, err := roundChangePayload(m)
	if err != nil {
		return nil, err
	}
	return rlp.Encode([]any{rlp.RawValue(p), m.Signature})
}

// ------------------------------------------------------------ PREPARE, COMMIT

func votePayload(m *Message) []any {
	return []any{m.View.Sequence.Big(), m.View.Round.Big(), m.Digest, m.Seal}
}

// voteRLP is [[sequence, round, digest, seal], signature].
type voteRLP struct {
	Payload struct {
		Sequence *big.Int
		Round    *big.Int
		Digest   types.Hash
		Seal     []byte
	}
	Signature []byte
}

func (v *voteRLP) message(code Code) *Message {
	return &Message{
		Code:      code,
		View:      types.View{Sequence: types.MustHeightFromBig(v.Payload.Sequence), Round: mustRound(v.Payload.Round)},
		Digest:    v.Payload.Digest,
		Seal:      v.Payload.Seal,
		Signature: v.Signature,
	}
}

func mustRound(b *big.Int) types.Round {
	r, err := types.RoundFromBig(b)
	if err != nil {
		panic(err) // decoded integers are never negative
	}
	return r
}

// Spec: WBFT-MSG-011
func decodeVote(code Code, payload []byte) (*Message, error) {
	var v voteRLP
	if err := rlp.DecodeStrict(payload, &v); err != nil {
		return nil, err
	}
	return v.message(code), nil
}

// ------------------------------------------------------------ ROUND-CHANGE

// roundChangePayload is rlp([sequence, round, prepared]) with prepared =
// [prepared_round, prepared_digest] when a prepared round is present and the
// digest is not zero, and [] otherwise.
//
// Spec: WBFT-MSG-030
func roundChangePayload(m *Message) ([]byte, error) {
	prepared := []any{}
	if m.PreparedRound != nil && m.PreparedDigest != (types.Hash{}) {
		prepared = []any{m.PreparedRound.Big(), m.PreparedDigest}
	}
	return rlp.Encode([]any{m.View.Sequence.Big(), m.View.Round.Big(), prepared})
}

// Spec: WBFT-MSG-031
func encodeRoundChange(m *Message) ([]byte, error) {
	p, err := roundChangePayload(m)
	if err != nil {
		return nil, err
	}
	block := rlp.RawValue(rlp.EmptyList)
	if m.PreparedBlock != nil {
		if block, err = EncodeBlock(m.PreparedBlock); err != nil {
			return nil, err
		}
	}
	just, err := encodeVoteList(m.Prepares)
	if err != nil {
		return nil, err
	}
	return rlp.Encode([]any{[]any{rlp.RawValue(p), m.Signature}, block, rlp.RawValue(just)})
}

func encodeVoteList(ms []*Message) ([]byte, error) {
	items := make([][]byte, len(ms))
	for i, p := range ms {
		b, err := EncodeMessage(p)
		if err != nil {
			return nil, err
		}
		items[i] = b
	}
	return rlp.EncodeList(items...), nil
}

// decodeSignedRoundChange reads [rc_payload, signature] from s into m, in the
// order of the reference decoder: the outer list, the payload as one raw
// item, then in the payload the sequence, the round and the prepared list of
// zero or two items, then the signature and the end of the outer list.
//
// Spec: WBFT-MSG-032, WBFT-MSG-034
func decodeSignedRoundChange(s *gethrlp.Stream, m *Message) error {
	if _, err := s.List(); err != nil {
		return err
	}
	payload, err := s.Raw()
	if err != nil {
		return err
	}
	ps := gethrlp.NewStream(bytes.NewReader(payload), 0)
	if _, err := ps.List(); err != nil {
		return err
	}
	var seq, round *big.Int
	if err := ps.Decode(&seq); err != nil {
		return err
	}
	if err := ps.Decode(&round); err != nil {
		return err
	}
	size, err := ps.List()
	if err != nil {
		return err
	}
	var preparedRound *big.Int
	var preparedDigest types.Hash
	if size > 0 {
		if err := ps.Decode(&preparedRound); err != nil {
			return err
		}
		if err := ps.Decode(&preparedDigest); err != nil {
			return err
		}
	}
	if err := ps.ListEnd(); err != nil { // end of prepared
		return err
	}
	if err := ps.ListEnd(); err != nil { // end of payload
		return err
	}
	var sig []byte
	if err := s.Decode(&sig); err != nil {
		return err
	}
	if err := s.ListEnd(); err != nil {
		return err
	}
	m.Code = CodeRoundChange
	m.View = types.View{Sequence: types.MustHeightFromBig(seq), Round: mustRound(round)}
	if preparedRound != nil {
		pr := mustRound(preparedRound)
		m.PreparedRound = &pr
	}
	m.PreparedDigest = preparedDigest
	m.Signature = sig
	return nil
}

// decodeRoundChange decodes [signed_payload, prepared_block, justification].
// An empty string, an empty list or a single byte in the prepared_block or
// justification position is read as absent. A prepared block must hash to
// the prepared digest.
//
// Spec: WBFT-MSG-032, WBFT-MSG-033
func decodeRoundChange(payload []byte) (*Message, error) {
	s, r := newStream(payload)
	m := &Message{}
	if _, err := s.List(); err != nil {
		return nil, err
	}
	if err := decodeSignedRoundChange(s, m); err != nil {
		return nil, err
	}
	// prepared block
	_, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if size == 0 {
		if _, err := s.Raw(); err != nil {
			return nil, err
		}
	} else {
		raw, err := s.Raw()
		if err != nil {
			return nil, err
		}
		b, err := DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		if BlockHash(b.Header) != m.PreparedDigest {
			return nil, errors.New("prepared block hash differs from the prepared digest")
		}
		m.PreparedBlock = b
	}
	// justification
	if _, size, err = s.Kind(); err != nil {
		return nil, err
	}
	if size == 0 {
		if _, err := s.Raw(); err != nil {
			return nil, err
		}
	} else {
		raw, err := s.Raw()
		if err != nil {
			return nil, err
		}
		if m.Prepares, err = decodeVoteList(raw); err != nil {
			return nil, err
		}
	}
	if err := s.ListEnd(); err != nil {
		return nil, err
	}
	if r.Len() > 0 {
		return nil, gethrlp.ErrMoreThanOneValue
	}
	return m, nil
}

// newStream returns a stream over exactly b and the reader that tells how
// many bytes are left after decoding.
func newStream(b []byte) (*gethrlp.Stream, *bytes.Reader) {
	r := bytes.NewReader(b)
	return gethrlp.NewStream(r, uint64(len(b))), r
}

// decodeVoteList decodes a list of PREPARE messages.
func decodeVoteList(raw []byte) ([]*Message, error) {
	var vs []*voteRLP
	if err := rlp.DecodeStrict(raw, &vs); err != nil {
		return nil, err
	}
	out := make([]*Message, len(vs))
	for i, v := range vs {
		out[i] = v.message(CodePrepare)
	}
	return out, nil
}

// ------------------------------------------------------------ PRE-PREPARE

func encodeProposal(b *types.Block) ([]byte, error) {
	if b == nil {
		return rlp.EmptyList, nil
	}
	return EncodeBlock(b)
}

// Spec: WBFT-MSG-040
func encodePreprepare(m *Message) ([]byte, error) {
	prop, err := encodeProposal(m.Proposal)
	if err != nil {
		return nil, err
	}
	rcs := make([][]byte, len(m.RoundChanges))
	for i, rc := range m.RoundChanges {
		if rcs[i], err = EncodeSignedRoundChange(rc); err != nil {
			return nil, err
		}
	}
	prepares, err := encodeVoteList(m.Prepares)
	if err != nil {
		return nil, err
	}
	signed := []any{[]any{m.View.Sequence.Big(), m.View.Round.Big(), rlp.RawValue(prop)}, m.Signature}
	just := []any{rlp.RawValue(rlp.EncodeList(rcs...)), rlp.RawValue(prepares)}
	return rlp.Encode([]any{signed, just})
}

// proposalRLP decodes a proposal block through DecodeBlock.
type proposalRLP struct{ b *types.Block }

func (p *proposalRLP) DecodeRLP(s *gethrlp.Stream) error {
	raw, err := s.Raw()
	if err != nil {
		return err
	}
	p.b, err = DecodeBlock(raw)
	return err
}

// preprepareRLP is [[[sequence, round, proposal], signature], [round_changes,
// prepares]]. Each round change is delimited as one raw item and decoded on
// its own.
type preprepareRLP struct {
	SignedPayload struct {
		Payload struct {
			Sequence *big.Int
			Round    *big.Int
			Proposal *proposalRLP
		}
		Signature []byte
	}
	Justification struct {
		RoundChanges []rlp.RawValue
		Prepares     []*voteRLP
	}
}

// Spec: WBFT-MSG-041
func decodePreprepare(payload []byte) (*Message, error) {
	var w preprepareRLP
	if err := rlp.DecodeStrict(payload, &w); err != nil {
		return nil, err
	}
	m := &Message{
		Code: CodePreprepare,
		View: types.View{
			Sequence: types.MustHeightFromBig(w.SignedPayload.Payload.Sequence),
			Round:    mustRound(w.SignedPayload.Payload.Round),
		},
		Signature: w.SignedPayload.Signature,
	}
	if w.SignedPayload.Payload.Proposal != nil {
		m.Proposal = w.SignedPayload.Payload.Proposal.b
	}
	for _, raw := range w.Justification.RoundChanges {
		s, r := newStream(raw)
		rc := &Message{}
		if err := decodeSignedRoundChange(s, rc); err != nil {
			return nil, err
		}
		if r.Len() > 0 {
			return nil, gethrlp.ErrMoreThanOneValue
		}
		m.RoundChanges = append(m.RoundChanges, rc)
	}
	for _, v := range w.Justification.Prepares {
		m.Prepares = append(m.Prepares, v.message(CodePrepare))
	}
	return m, nil
}
