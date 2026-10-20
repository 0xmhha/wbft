package header

import (
	"errors"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// ErrSnapshotMismatch reports candidate input bound to another parent.
var ErrSnapshotMismatch = errors.New("authority snapshot does not match the parent")

// epochProposalContext selects activation using the actual parent before the
// supplied number can classify itself as genesis or another epoch.
func epochProposalContext(env *Env, h *types.Header, parents []*types.Header) (bool, error) {
	if _, configured := env.Config.RuleActivation(types.EpochInfoInProposal); !configured {
		return false, nil
	}
	if h == nil {
		return false, ErrInvalidProposal
	}
	if h.Number.IsZero() && h.ParentHash == (types.Hash{}) {
		return false, nil
	}
	parent := bitmapAncestor(env, parents, h.ParentHash)
	if parent == nil || codec.BlockHash(parent) != h.ParentHash {
		return false, stepErr("epoch_info", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	next := parent.Number.AddUint64(1)
	active := env.Config.Rules(types.EpochInfoInProposal, next)
	if active && h.Number.Cmp(next) != 0 {
		return false, stepErr("epoch_info", "ErrInvalidNumber", ErrInvalidNumber)
	}
	return active, nil
}

func verifyProposedEpoch(env *Env, h, parent *types.Header, parents []*types.Header, x *types.WBFTExtra, opt Options) error {
	active, err := epochProposalContext(env, h, parents)
	if err != nil || !active {
		return err
	}
	isEpoch, err := validator.IsEpochBlock(env.Config, h.Number)
	if err != nil {
		return err
	}
	if !isEpoch {
		return epoch.CheckNoEpochInfo(h)
	}
	if x.EpochInfo == nil {
		return validator.ErrEpochInfoNil
	}
	if env.Snapshots != nil {
		if snapshot, ok := env.Snapshots.Get(h.ParentHash); ok && snapshot != nil {
			if snapshot.Hash() != h.ParentHash || snapshot.Number().Cmp(parent.Number) != 0 {
				return ErrSnapshotMismatch
			}
			if snapshot.HasCandidates() {
				return epoch.VerifyEpochInfo(epochPendingChain{env.Chain, parents}, env.Config, h, snapshot.Candidates())
			}
		}
	}
	if opt.Mode == Proposal {
		return ErrSnapshotMissing
	}
	// Header-only synchronization can precede execution of its parents. The
	// application must check the epoch information when it executes the block.
	return nil
}

// epochPendingChain supplies hash-bound ancestry that is still in a header batch.
type epochPendingChain struct {
	types.ChainReader
	parents []*types.Header
}

func (c epochPendingChain) HeaderByHash(hash types.Hash) *types.Header {
	for i := len(c.parents) - 1; i >= 0; i-- {
		if h := c.parents[i]; h != nil && codec.BlockHash(h) == hash {
			return h
		}
	}
	return c.ChainReader.HeaderByHash(hash)
}
