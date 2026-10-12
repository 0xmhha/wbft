package header

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// verifyNumber uses the parent's full number to select the chain rule.
// The candidate number never chooses its own activation height.
func verifyNumber(env *Env, h *types.Header, parents []*types.Header) error {
	if _, configured := env.Config.RuleActivation(types.RejectNumberJump); !configured {
		return nil
	}
	if h == nil {
		return ErrInvalidProposal
	}
	if h.Number.IsZero() && h.ParentHash == (types.Hash{}) {
		return nil // genesis has no parent
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = env.Chain.HeaderByHash(h.ParentHash)
	}
	if parent == nil || codec.BlockHash(parent) != h.ParentHash {
		return stepErr("number", "ErrUnknownAncestor", ErrUnknownAncestor)
	}
	at := parent.Number.AddUint64(1)
	if env.Config.Rules(types.RejectNumberJump, at) && (!h.Number.IsUint64() || h.Number.Cmp(at) != 0) {
		return stepErr("number", "ErrInvalidNumber", ErrInvalidNumber)
	}
	return nil
}
