package stepdriver

import (
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type traceObservation struct {
	options *journal.ObservationOptions
	engine  *window.Engine
	rules   *types.Config
	blocks  BlockSource
	state   *window.State
	anchor  types.Hash
	active  types.Height
	floor   types.Height
}

func newTraceObservation(segment *journal.SegmentRec, rules *types.Config, blocks BlockSource) (*traceObservation, error) {
	options := segment.Core.Observation
	if options == nil {
		return nil, nil
	}
	if err := options.ValidateIdentity(segment.ChainID, segment.GenesisHash); err != nil {
		return nil, err
	}
	if blocks == nil {
		return nil, fmt.Errorf("stepdriver: observation replay requires an independent chain source")
	}
	if _, err := headOf(blocks, types.Height{}, options.GenesisHash); err != nil {
		return nil, err
	}
	engine, err := options.Engine()
	if err != nil {
		return nil, err
	}
	activation, _ := new(big.Int).SetString(options.Activation, 10) // Engine checked canonical decimal form.
	r := &traceObservation{options: options, engine: engine, rules: rules, blocks: blocks, active: types.MustHeightFromBig(activation)}
	if len(options.Checkpoint) != 0 {
		var hint struct {
			Version uint64
			Height  *big.Int
			Hash    types.Hash
			State   rlp.RawValue
		}
		if err := rlp.DecodeStrict(options.Checkpoint, &hint); err != nil || hint.Height == nil || hint.Height.Sign() < 0 {
			return nil, window.ErrState
		}
		// The recorded coordinates only locate a header in caller-supplied
		// canonical blocks. They cannot authenticate their own state.
		trusted, err := headOf(blocks, types.MustHeightFromBig(hint.Height), hint.Hash)
		if err != nil {
			return nil, err
		}
		r.state, err = engine.Recover(options.Checkpoint, trusted)
		if err != nil {
			return nil, err
		}
		r.anchor = codec.BlockHash(trusted)
		r.floor = trusted.Number
	}
	return r, nil
}

func (r *traceObservation) check(number types.Height, hash types.Hash) error {
	if r == nil {
		return nil
	}
	if number.Cmp(r.floor) < 0 {
		return window.ErrHistory
	}
	head, err := headOf(r.blocks, number, hash)
	if err != nil {
		return err
	}
	if head.Number.Cmp(r.active) < 0 {
		_, err := codec.DecodeExtra(head)
		return err
	}
	chain := chainOf{r.blocks}
	current := head
	state := r.state
	var suffix []*types.Header
	for state == nil || codec.BlockHash(current) != r.anchor {
		if current.Number.AddUint64(1).Cmp(r.active) == 0 {
			state, err = r.engine.Initial(current)
			if err != nil {
				return err
			}
			break
		}
		if current.Number.Cmp(r.active) < 0 || uint64(len(suffix)) >= r.options.ReplayHeaders {
			return window.ErrHistory
		}
		suffix = append(suffix, current)
		previous := chain.HeaderByHash(current.ParentHash)
		if previous == nil || previous.Number.AddUint64(1).Cmp(current.Number) != 0 || codec.BlockHash(previous) != current.ParentHash {
			return window.ErrHistory
		}
		current = previous
	}
	history, err := window.NewBranchHistory(r.engine, chain, r.rules, r.options.HistoryWalk)
	if err != nil {
		return err
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		state, err = r.engine.VerifyAndApply(state, suffix[i], history)
		if err != nil {
			return err
		}
	}
	r.state, r.anchor = state, hash
	return nil
}
