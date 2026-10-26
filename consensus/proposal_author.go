package consensus

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// proposalAuthorAllowed runs after the ordinary proposer and justification
// checks. The supplied PREPAREs must already have recovered member signatures.
// A prepared certificate permits the original block author to survive a later
// proposer; a fresh proposal must belong to its authenticated sender.
func proposalAuthorAllowed(sender types.Address, target types.View, block *types.Block, prepares []*Verified, quorum int) bool {
	if block == nil || block.Header == nil || block.Header.Number.Cmp(target.Sequence) != 0 {
		return false
	}
	if len(prepares) == 0 {
		return block.Header.Coinbase == sender
	}
	if target.Round.IsZero() || quorum <= 0 {
		return false
	}
	digest := blockHash(block)
	var preparedRound types.Round
	seen := make(map[types.Address]struct{}, len(prepares))
	for i, verified := range prepares {
		if verified == nil || verified.Msg == nil {
			return false
		}
		msg := verified.Msg
		if msg.Code != codec.CodePrepare || msg.View.Sequence.Cmp(target.Sequence) != 0 || msg.View.Round.Cmp(target.Round) >= 0 || msg.Digest != digest {
			return false
		}
		if i == 0 {
			preparedRound = msg.View.Round
		} else if msg.View.Round.Cmp(preparedRound) != 0 {
			return false
		}
		seen[verified.Source] = struct{}{}
	}
	return len(seen) >= quorum
}
