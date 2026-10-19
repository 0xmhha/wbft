package header

import (
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// minimalBitmap permits an absent seal and the empty representation of an
// empty set. A nonempty bitmap ends with its highest occupied byte.
func minimalBitmap(seal *types.AggregatedSeal) bool {
	return seal == nil || len(seal.Sealers) == 0 || seal.Sealers[len(seal.Sealers)-1] != 0
}

// verifyCurrentBitmaps checks representation separately from signature checks,
// including when the caller is verifying a proposal without its own seals.
func verifyCurrentBitmaps(cfg *types.Config, parent *types.Header, x *types.WBFTExtra) error {
	at := types.Height{}
	if parent != nil {
		at = parent.Number.AddUint64(1)
	}
	if !cfg.Rules(types.MinimalSealerBitmap, at) {
		return nil
	}
	for _, part := range []struct {
		seal *types.AggregatedSeal
		err  error
	}{{x.PreparedSeal, ErrInvalidPreparedSeals}, {x.CommittedSeal, ErrInvalidCommittedSeals}} {
		if !minimalBitmap(part.seal) {
			err := fmt.Errorf("%w: %w", part.err, ErrNonMinimalSealerBitmap)
			return stepErr("H17", className(err), err)
		}
	}
	return nil
}

// Previous seals describe the parent. The first child of an activation block
// checks them; the activation block still accepts its preceding representation.
func verifyPreviousBitmaps(cfg *types.Config, parent *types.Header, x *types.WBFTExtra, ancestor func(types.Hash) *types.Header) error {
	if minimalBitmap(x.PrevPreparedSeal) && minimalBitmap(x.PrevCommittedSeal) {
		return nil
	}
	activation, configured := cfg.RuleActivation(types.MinimalSealerBitmap)
	if !configured {
		return nil
	}
	at := types.Height{}
	if parent != nil && (!parent.Number.IsZero() || parent.ParentHash != (types.Hash{})) && !activation.IsZero() {
		var grandparent *types.Header
		if ancestor != nil {
			grandparent = ancestor(parent.ParentHash)
		}
		if grandparent == nil || codec.BlockHash(grandparent) != parent.ParentHash {
			return stepErr("H20", "ErrUnknownAncestor", ErrUnknownAncestor)
		}
		at = grandparent.Number.AddUint64(1)
	}
	if !cfg.Rules(types.MinimalSealerBitmap, at) {
		return nil
	}

	for _, part := range []struct {
		seal *types.AggregatedSeal
		err  error
	}{{x.PrevPreparedSeal, ErrInvalidPrevPreparedSeals}, {x.PrevCommittedSeal, ErrInvalidPrevCommittedSeals}} {
		if !minimalBitmap(part.seal) {
			err := fmt.Errorf("%w: %w", part.err, ErrNonMinimalSealerBitmap)
			return stepErr("H20", className(err), err)
		}
	}
	return nil
}

// bitmapAncestor uses the explicit batch before consulting stored history.
func bitmapAncestor(env *Env, parents []*types.Header, hash types.Hash) *types.Header {
	for i := len(parents) - 1; i >= 0; i-- {
		if parents[i] != nil && codec.BlockHash(parents[i]) == hash {
			return parents[i]
		}
	}
	return env.Chain.HeaderByHash(hash)
}
