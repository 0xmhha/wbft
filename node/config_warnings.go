package node

import (
	"fmt"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// warnSameBlockTransitions reports repeated heights without changing how
// configuration fields are applied in their existing order.
func (n *Node) warnSameBlockTransitions(cfg *types.Config) {
	transitions := cfg.Transitions()
	for i := 0; i < len(transitions); {
		j := i + 1
		for j < len(transitions) && transitions[j].Block.Cmp(transitions[i].Block) == 0 {
			j++
		}
		if j-i > 1 {
			block := transitions[i].Block.String()
			reason := fmt.Sprintf("%d transitions at block %s retain their configured application order", j-i, block)
			n.log.Warn("multiple transitions share a block", "block", block, "count", j-i)
			n.emit(event.Record{Kind: event.Health, Fields: map[string]any{
				"what": "same_block_transitions", "reason": reason,
			}})
		}
		i = j
	}
}
