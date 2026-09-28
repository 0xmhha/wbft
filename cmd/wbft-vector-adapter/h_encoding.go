package main

import (
	"encoding/json"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// Handlers of the runner "encoding" (A-03).

func sealOut(s *types.AggregatedSeal) any {
	if s == nil {
		return nil
	}
	return obj{"sealers": hexOut(s.Sealers), "signature": hexOut(s.Signature)}
}

func epochInfoOut(e *types.EpochInfo) any {
	if e == nil {
		return nil
	}
	cands := make([]any, len(e.Candidates))
	for i, c := range e.Candidates {
		cands[i] = obj{"addr": addrOut(c.Addr), "diligence": decOut(c.Diligence)}
	}
	vals := make([]any, len(e.Validators))
	for i, v := range e.Validators {
		vals[i] = decOut(uint64(v))
	}
	return obj{"candidates": cands, "validators": vals, "bls_public_keys": hexList(e.BLSPublicKeys)}
}

func hExtraCodec(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Extra Hex `json:"extra"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	x, err := codec.DecodeExtraBytes(in.Extra)
	if err != nil {
		return nil, err
	}
	enc, err := codec.EncodeExtra(x)
	if err != nil {
		return nil, err
	}
	return obj{
		"vanity_data":         hexOut(x.VanityData),
		"randao_reveal":       hexOut(x.RandaoReveal),
		"prev_round":          decOut(uint64(x.PrevRound)),
		"prev_prepared_seal":  sealOut(x.PrevPreparedSeal),
		"prev_committed_seal": sealOut(x.PrevCommittedSeal),
		"round":               decOut(uint64(x.Round)),
		"prepared_seal":       sealOut(x.PreparedSeal),
		"committed_seal":      sealOut(x.CommittedSeal),
		"gas_tip":             bigOut(x.GasTip),
		"epoch_info":          epochInfoOut(x.EpochInfo),
		"encoded":             hexOut(enc),
	}, nil
}

func hBlockHash(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Header Hex `json:"header"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	h, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	hash := codec.BlockHash(h)
	return obj{"hash": hexOut(hash[:])}, nil
}

type headerRoundInput struct {
	Header Hex `json:"header"`
	Round  Dec `json:"round"`
}

func (in *headerRoundInput) parse(input json.RawMessage) (*types.Header, uint32, error) {
	if err := decode(input, in); err != nil {
		return nil, 0, err
	}
	h, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, 0, err
	}
	r, err := toUint32(in.Round)
	return h, r, err
}

func hHashWithRound(_ string, input json.RawMessage) (any, error) {
	var in headerRoundInput
	h, r, err := in.parse(input)
	if err != nil {
		return nil, err
	}
	hash := codec.HashWithRound(h, r)
	return obj{"hash": hexOut(hash[:])}, nil
}

func hFilteredHeader(_ string, input json.RawMessage) (any, error) {
	var in headerRoundInput
	h, r, err := in.parse(input)
	if err != nil {
		return nil, err
	}
	fh, err := codec.FilteredHeader(h, r)
	if err != nil {
		return nil, err
	}
	b, err := codec.EncodeHeader(fh)
	if err != nil {
		return nil, err
	}
	return obj{"header": hexOut(b)}, nil
}

type messageInput struct {
	Code    Dec `json:"code"`
	Payload Hex `json:"payload"`
}

func (in *messageInput) parse(input json.RawMessage) (*codec.Message, error) {
	if err := decode(input, in); err != nil {
		return nil, err
	}
	code, err := in.Code.Uint64Checked()
	if err != nil {
		return nil, err
	}
	return codec.DecodeMessage(codec.Code(code), in.Payload)
}

var codeNames = map[codec.Code]string{
	codec.CodePreprepare:  "PREPREPARE",
	codec.CodePrepare:     "PREPARE",
	codec.CodeCommit:      "COMMIT",
	codec.CodeRoundChange: "ROUND_CHANGE",
}

func encodeList(ms []*Message, enc func(*Message) ([]byte, error)) ([]any, error) {
	out := make([]any, len(ms))
	for i, m := range ms {
		b, err := enc(m)
		if err != nil {
			return nil, err
		}
		out[i] = hexOut(b)
	}
	return out, nil
}

// Message is codec.Message (a short name for the helpers of this file).
type Message = codec.Message

func hMessageCodec(_ string, input json.RawMessage) (any, error) {
	var in messageInput
	m, err := in.parse(input)
	if err != nil {
		return nil, err
	}
	out := obj{
		"type":      codeNames[m.Code],
		"sequence":  m.View.Sequence.String(),
		"round":     m.View.Round.String(),
		"signature": hexOut(m.Signature),
	}
	switch m.Code {
	case codec.CodePrepare, codec.CodeCommit:
		out["digest"] = hexOut(m.Digest[:])
		out["seal"] = hexOut(m.Seal)
	case codec.CodeRoundChange:
		var pr any
		if m.PreparedRound != nil {
			pr = m.PreparedRound.String()
		}
		out["prepared_round"] = pr
		out["prepared_digest"] = hexOut(m.PreparedDigest[:])
		var pb any
		if m.PreparedBlock != nil {
			b, err := codec.EncodeBlock(m.PreparedBlock)
			if err != nil {
				return nil, err
			}
			pb = hexOut(b)
		}
		out["prepared_block"] = pb
		if out["justification"], err = encodeList(m.Prepares, codec.EncodeMessage); err != nil {
			return nil, err
		}
	case codec.CodePreprepare:
		prop := []byte{0xc0}
		if m.Proposal != nil {
			if prop, err = codec.EncodeBlock(m.Proposal); err != nil {
				return nil, err
			}
		}
		out["proposal"] = hexOut(prop)
		if out["justification_round_changes"], err = encodeList(m.RoundChanges, codec.EncodeSignedRoundChange); err != nil {
			return nil, err
		}
		if out["justification_prepares"], err = encodeList(m.Prepares, codec.EncodeMessage); err != nil {
			return nil, err
		}
	}
	enc, err := codec.EncodeMessage(m)
	if err != nil {
		return nil, err
	}
	out["encoded"] = hexOut(enc)
	return out, nil
}

// signer returns the signing payload of m and the address recovered from its
// signature.
func signer(m *codec.Message) (obj, error) {
	p, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		return nil, err
	}
	a, err := ecdsa.RecoverDataSigner(p, m.Signature)
	if err != nil {
		return nil, err
	}
	return obj{"signing_payload": hexOut(p), "signer": addrOut(a)}, nil
}

func hSigningPayload(_ string, input json.RawMessage) (any, error) {
	var in messageInput
	m, err := in.parse(input)
	if err != nil {
		return nil, err
	}
	out, err := signer(m)
	if err != nil {
		return nil, err
	}
	var embedded []*codec.Message
	switch m.Code {
	case codec.CodeRoundChange:
		embedded = m.Prepares
	case codec.CodePreprepare:
		embedded = append(append(embedded, m.RoundChanges...), m.Prepares...)
	}
	emb := make([]any, 0, len(embedded))
	for _, e := range embedded {
		o, err := signer(e)
		if err != nil {
			return nil, err
		}
		emb = append(emb, o)
	}
	out["embedded"] = emb
	return out, nil
}

func hDedupKey(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Payload Hex `json:"payload"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	k := codec.DedupKey(in.Payload)
	return obj{"key": hexOut(k[:])}, nil
}
