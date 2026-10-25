package app

import (
	"context"
	"github.com/0xmhha/wbft/types"
)

// ObservationConsensus wraps a fully prepared candidate after legacy epoch
// fields have been computed and before its hash, receipts or signatures are
// cached. Disabled services return the candidate unchanged.
type ObservationConsensus interface {
	PrepareObservation(context.Context, *types.Header) (*types.Header, error)
}

// PrepareObservation preserves applications with no observation extension.
func PrepareObservation(ctx context.Context, consensus Consensus, h *types.Header) (*types.Header, error) {
	if extension, ok := consensus.(ObservationConsensus); ok {
		return extension.PrepareObservation(ctx, h)
	}
	return h, nil
}
