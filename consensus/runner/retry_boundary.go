package runner

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
)

const roundChangeRetryFormat uint8 = 4

var errRoundChangeRetryWAL = errors.New("runner: round-change retry WAL requires matching options and replay profile")

type retryBoundaryRLP struct {
	Version      uint64
	MaximumMs    uint64
	Improvements uint64
	Format       uint64
	Boundary     []byte
}

// The new profile wraps exact prior boundary bytes. A disabled policy never
// writes this wrapper and keeps the existing format one, two or three.
func encodeRetryBoundary(base wal.Record, maximum uint64, improvements consensus.ImprovementSet) (wal.Record, error) {
	if base.Kind != walRunStart && base.Kind != walEndHeight || base.Format != walFormat && base.Format != nextHeightFormat && base.Format != priorHeadFormat ||
		maximum == 0 || maximum > uint64(math.MaxInt64/int64(time.Millisecond)) || improvements&^consensus.KnownImprovements() != 0 {
		return wal.Record{}, errRoundChangeRetryWAL
	}
	w := retryBoundaryRLP{Version: 1, MaximumMs: maximum, Improvements: uint64(improvements), Format: uint64(base.Format), Boundary: base.Body}
	body, err := rlp.Encode(&w)
	if err != nil {
		return wal.Record{}, err
	}
	return wal.Record{Format: roundChangeRetryFormat, Kind: base.Kind, Body: body}, nil
}

func decodeRetryBoundary(rec wal.Record) (wal.Record, uint64, uint64, error) {
	if rec.Format != roundChangeRetryFormat || rec.Kind != walRunStart && rec.Kind != walEndHeight {
		return wal.Record{}, 0, 0, errRoundChangeRetryWAL
	}
	var w retryBoundaryRLP
	if err := rlp.DecodeStrict(rec.Body, &w); err != nil || w.Version != 1 ||
		w.MaximumMs == 0 || w.MaximumMs > uint64(math.MaxInt64/int64(time.Millisecond)) ||
		w.Improvements&^uint64(consensus.KnownImprovements()) != 0 ||
		w.Format != uint64(walFormat) && w.Format != uint64(nextHeightFormat) && w.Format != uint64(priorHeadFormat) {
		return wal.Record{}, 0, 0, errRoundChangeRetryWAL
	}
	return wal.Record{Format: uint8(w.Format), Kind: rec.Kind, Body: w.Boundary}, w.MaximumMs, w.Improvements, nil
}

func (r *Runner) checkRetryBoundary(rec wal.Record, b boundaryRec, pending *deferredBoundary) error {
	policy := r.cfg.Core.RoundChangeRetry
	if policy == nil {
		if rec.Format == roundChangeRetryFormat || b.retryMaximumMs != 0 {
			return errRoundChangeRetryWAL
		}
		return nil
	}
	if rec.Format != roundChangeRetryFormat || b.retryMaximumMs != policy.MaxIntervalMs || b.retryImprovements != uint64(r.cfg.Core.Improvements) {
		return fmt.Errorf("%w: boundary parameters differ", errRoundChangeRetryWAL)
	}
	if (b.PriorSource != nil) != r.cfg.Core.Improvements.Has(consensus.BindPriorHead) || (pending != nil) != (r.nextHeight != nil) {
		return fmt.Errorf("%w: wrapped runtime profile differs", errRoundChangeRetryWAL)
	}
	return nil
}
