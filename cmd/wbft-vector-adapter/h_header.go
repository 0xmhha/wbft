package main

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/internal/snetpartb"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
	"github.com/0xmhha/wbft/validator/source"
)

// Handlers of the runner "header" (A-08). A chain fixture carries no state,
// so the environment has no authority snapshots and header verification runs
// in HeaderOnly mode: H15b and H21 are skipped.

func nowAt(sec uint64) func() time.Time {
	t := time.Unix(int64(sec), 0)
	return func() time.Time { return t }
}

func verdict(err error) string {
	switch {
	case err == nil:
		return "accept"
	case errors.Is(err, header.ErrFutureBlock):
		return "deferred"
	default:
		return "reject"
	}
}

func headerEnv(f *fixtureIn, now Dec) (*header.Env, error) {
	chain, cfg, fk, err := f.build()
	if err != nil {
		return nil, err
	}
	sec, err := now.Uint64Checked()
	if err != nil {
		return nil, err
	}
	return &header.Env{
		Config: cfg,
		Chain:  chain,
		PartB:  &snetpartb.PartB{Forks: fk},
		Now:    nowAt(sec),
	}, nil
}

var verifyOptions = header.Options{CheckSeals: true, Mode: header.HeaderOnly}

func hVerifyHeader(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Chain  fixtureIn `json:"chain"`
		Header Hex       `json:"header"`
		Now    Dec       `json:"now"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	env, err := headerEnv(&in.Chain, in.Now)
	if err != nil {
		return nil, err
	}
	h, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	return obj{"verdict": verdict(header.VerifyHeader(env, h, nil, verifyOptions))}, nil
}

func hVerifyHeaders(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Chain   fixtureIn `json:"chain"`
		Headers []Hex     `json:"headers"`
		Now     Dec       `json:"now"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	env, err := headerEnv(&in.Chain, in.Now)
	if err != nil {
		return nil, err
	}
	hs := make([]*types.Header, len(in.Headers))
	for i, b := range in.Headers {
		if hs[i], err = codec.DecodeHeader(b); err != nil {
			return nil, err
		}
	}
	out := make([]any, 0, len(hs))
	for _, err := range header.VerifyHeaderBatch(env, hs, verifyOptions) {
		out = append(out, verdict(err))
	}
	return obj{"verdicts": out}, nil
}

// fixtureTrust derives the validator sets of a light verifier from the
// headers of a fixture, which the vectors treat as accepted.
type fixtureTrust struct {
	chain types.ChainReader
	cfg   *types.Config
}

func (t *fixtureTrust) ValidatorsAt(n types.Height, parentHash types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(t.chain, t.cfg, n, parentHash, nil)
}

func hVerifyLight(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Chain  fixtureIn `json:"chain"`
		Header Hex       `json:"header"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	chain, cfg, fk, err := in.Chain.build()
	if err != nil {
		return nil, err
	}
	h, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	res, _ := header.VerifyLight(header.LightInputs{
		Config:  cfg,
		Trusted: &fixtureTrust{chain: chain, cfg: cfg},
		PartB:   &snetpartb.PartB{Forks: fk},
	}, h, chain.HeaderByHash(h.ParentHash))
	return obj{"result": res.String()}, nil
}

// keySigner signs randao data with a node key.
type keySigner struct{ key *ecdsa.PrivateKey }

func (s keySigner) SignRandao(data []byte) ([]byte, error) { return ecdsa.SignData(data, s.key) }

func hBuildProposalHeader(_ string, input json.RawMessage) (any, error) {
	type sealIn struct {
		Sealer Dec `json:"sealer"`
		Seal   Hex `json:"seal"`
	}
	var in struct {
		Chain          fixtureIn `json:"chain"`
		Header         Hex       `json:"header"`
		NodeKey        Hex       `json:"node_key"`
		GasTip         *Dec      `json:"gas_tip"`
		ExtraPrepared  []sealIn  `json:"extra_prepared"`
		ExtraCommitted []sealIn  `json:"extra_committed"`
		Now            Dec       `json:"now"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	env, err := headerEnv(&in.Chain, in.Now)
	if err != nil {
		return nil, err
	}
	skeleton, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.PrivateKeyFromBytes(in.NodeKey)
	if err != nil {
		return nil, err
	}
	seals := func(ss []sealIn) ([]types.SealEntry, error) {
		out := make([]types.SealEntry, len(ss))
		for i, s := range ss {
			idx, err := toUint32(s.Sealer)
			if err != nil {
				return nil, err
			}
			out[i] = types.SealEntry{Sealer: idx, Seal: s.Seal}
		}
		return out, nil
	}
	pin := header.ProposalInputs{Coinbase: ecdsa.Address(key), Signer: keySigner{key}}
	if pin.ExtraPrepared, err = seals(in.ExtraPrepared); err != nil {
		return nil, err
	}
	if pin.ExtraCommitted, err = seals(in.ExtraCommitted); err != nil {
		return nil, err
	}
	if in.GasTip != nil {
		if pin.ParentGasTip, err = source.GasTipFromBig(&in.GasTip.Int); err != nil {
			return nil, err
		}
	}
	h, err := header.PrepareProposal(env, skeleton, pin)
	if err != nil {
		return nil, err
	}
	b, err := codec.EncodeHeader(h)
	if err != nil {
		return nil, err
	}
	return obj{"header": hexOut(b)}, nil
}
