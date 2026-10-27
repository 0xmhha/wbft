package journal

import (
	"bytes"
	"errors"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

var errRestoreNextHeight = errors.New("journal: deferred restore reconstruction unavailable")

// This decoder is independent of the runner's boundary decoder and planner.
// It reconstructs the ordinary boundary profile; the deferred ledger still
// requires its own independent reconstruction before it can be accepted.
type restorePriorWire struct {
	Version  uint64
	Format   uint64
	Boundary []byte
	HeadHash types.Hash
	Round    uint64
	Source   []byte
}

func decodeRestoreBoundary(format uint8, body []byte) (restoreBoundary, *consensus.PriorHeadSource, error) {
	var b restoreBoundary
	var w restorePriorWire
	switch format {
	case 1:
		err := rlp.DecodeStrict(body, &b)
		return b, nil, err
	case 2:
		return b, nil, errRestoreNextHeight
	case 3:
		if rlp.DecodeStrict(body, &w) != nil || w.Version != 1 || w.Format != 1 && w.Format != 2 {
			return b, nil, ErrRestoreSource
		}
		if w.Format == 2 {
			return b, nil, errRestoreNextHeight
		}
	default:
		return b, nil, ErrRestoreSource
	}
	if rlp.DecodeStrict(w.Boundary, &b) != nil {
		return b, nil, ErrRestoreSource
	}
	head, err := codec.DecodeHeader(b.Head)
	if err != nil || head == nil || b.From == nil || b.From.Cmp(head.Number.AddUint64(1).Big()) != 0 {
		return b, nil, ErrRestoreSource
	}
	c, err := inputlog.DecodeEnv(w.Source)
	if err != nil || c.Kind != inputlog.EnvValidatorsAt || c.Result != 0 || c.Future != 0 || c.Step != "" || c.Class != "" || c.Bad || c.Validators == nil && c.Err != "prior_source_unavailable" || c.Validators != nil && c.Err != "" {
		return b, nil, ErrRestoreSource
	}
	canonical, err := inputlog.EncodeEnv(c)
	if err != nil || !bytes.Equal(canonical, w.Source) {
		return b, nil, ErrRestoreSource
	}
	p, err := consensus.NewPriorHeadSource(head, c.Validators)
	if err != nil || !p.MatchesLookup(c.Number, c.Key) || p.Hash != w.HeadHash || p.Round.Cmp(types.RoundFromUint64(w.Round)) != 0 {
		return b, nil, ErrRestoreSource
	}
	return b, p, nil
}
