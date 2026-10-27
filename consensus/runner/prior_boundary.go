package runner

import (
	"bytes"
	"errors"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

const priorHeadFormat uint8 = 3

var errPriorHeadWAL = errors.New("runner: prior-head WAL requires matching option and replay profile")

var errPriorBoundary = errors.New("runner: invalid prior-head source boundary")

type priorBoundaryRLP struct {
	Version  uint64
	Format   uint64
	Boundary []byte
	HeadHash types.Hash
	Round    uint64
	Source   []byte
}

// encodePriorBoundary preserves the exact legacy or deferred boundary body.
// Its source is a local adopted-state assertion, not independent chain proof.
func encodePriorBoundary(base wal.Record, p *consensus.PriorHeadSource, head *types.Header) (wal.Record, error) {
	if base.Format != walFormat && base.Format != nextHeightFormat || base.Kind != walRunStart && base.Kind != walEndHeight || p.ValidateHead(head) != nil {
		return wal.Record{}, errPriorBoundary
	}
	b, _, err := decodeRunnerBoundary(base)
	if err != nil || p.ValidateHead(b.Head) != nil || b.From.Cmp(head.Number.AddUint64(1)) != 0 {
		return wal.Record{}, errPriorBoundary
	}
	call := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: p.Number, Key: p.Parent, Validators: p.Validators}
	if p.Validators == nil {
		call.Err = "prior_source_unavailable"
	}
	raw, err := inputlog.EncodeEnv(call)
	if err != nil {
		return wal.Record{}, err
	}
	w := priorBoundaryRLP{Version: 1, Format: uint64(base.Format), Boundary: base.Body, HeadHash: p.Hash, Round: p.Round.Big().Uint64(), Source: raw}
	body, err := rlp.Encode(&w)
	return wal.Record{Format: priorHeadFormat, Kind: base.Kind, Body: body}, err
}

func decodePriorBoundary(rec wal.Record) (wal.Record, *consensus.PriorHeadSource, error) {
	if rec.Format != priorHeadFormat || rec.Kind != walRunStart && rec.Kind != walEndHeight {
		return wal.Record{}, nil, errPriorBoundary
	}
	var w priorBoundaryRLP
	if rlp.DecodeStrict(rec.Body, &w) != nil || w.Version != 1 || w.Format != walFormat && w.Format != uint64(nextHeightFormat) {
		return wal.Record{}, nil, errPriorBoundary
	}
	base := wal.Record{Format: uint8(w.Format), Kind: rec.Kind, Body: w.Boundary}
	b, _, err := decodeRunnerBoundary(base)
	if err != nil || b.Head == nil || b.From.Cmp(b.Head.Number.AddUint64(1)) != 0 {
		return wal.Record{}, nil, errPriorBoundary
	}
	call, err := inputlog.DecodeEnv(w.Source)
	if err != nil || call.Kind != inputlog.EnvValidatorsAt || call.Result != 0 || call.Future != 0 || call.Step != "" || call.Class != "" || call.Bad || call.Validators == nil && call.Err != "prior_source_unavailable" || call.Validators != nil && call.Err != "" {
		return wal.Record{}, nil, errPriorBoundary
	}
	canonical, err := inputlog.EncodeEnv(call)
	if err != nil || !bytes.Equal(canonical, w.Source) {
		return wal.Record{}, nil, errPriorBoundary
	}
	p, err := consensus.NewPriorHeadSource(b.Head, call.Validators)
	if err != nil || !p.MatchesLookup(call.Number, call.Key) || p.Hash != w.HeadHash || p.Round.Cmp(types.RoundFromUint64(w.Round)) != 0 {
		return wal.Record{}, nil, errPriorBoundary
	}
	return base, p, nil
}
