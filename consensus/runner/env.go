package runner

import (
	"errors"
	"fmt"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// envAnswer is one recorded Env call.
type envAnswer struct {
	call inputlog.EnvCall
}

// liveEnv answers the core from the application and records every answer
// in the write-ahead log and for the journal.
type liveEnv struct {
	r       *Runner
	head    *types.Header
	record  bool
	answers []envAnswer
}

func (e *liveEnv) begin(record bool) { e.record, e.answers = record, nil }

func (e *liveEnv) end() []envAnswer {
	a := e.answers
	e.answers = nil
	return a
}

func (e *liveEnv) note(c inputlog.EnvCall) {
	e.answers = append(e.answers, envAnswer{call: c})
	if !e.record || e.r.d.WAL == nil {
		return
	}
	b, err := inputlog.EncodeEnv(c)
	if err == nil {
		_, err = e.r.d.WAL.Append(encodeEnv(b))
	}
	if err != nil {
		e.r.halt(err)
	}
}

func (e *liveEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}

func (e *liveEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	vs, err := e.r.d.Chain.ValidatorsAt(n, parent)
	c := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: n, Key: parent, Validators: vs}
	if err != nil {
		c.Validators, c.Err = nil, err.Error()
	}
	e.note(c)
	return vs, err
}

func (e *liveEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	d, err := e.r.d.Chain.ValidateProposal(b)
	e.note(inputlog.ProposalCall(codec.BlockHash(b.Header), d, err))
	return d, err
}

func (e *liveEnv) IsBadBlock(h types.Hash) bool {
	bad := e.r.d.Chain.IsBadBlock(h)
	e.note(inputlog.EnvCall{Kind: inputlog.EnvIsBadBlock, Key: h, Bad: bad})
	return bad
}

func (e *liveEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}

// errReplayShort reports a replayed step that asked for an Env answer the
// log does not hold.
var errReplayShort = errors.New("runner: replay needs an Env answer the log does not hold")

// replayEnv answers the core from recorded Env answers, in order.
type replayEnv struct {
	head    *types.Header
	answers []inputlog.EnvCall
	used    []inputlog.EnvCall
	err     error
}

func (e *replayEnv) pop(kind uint8, key types.Hash) (inputlog.EnvCall, bool) {
	if e.err != nil {
		return inputlog.EnvCall{}, false
	}
	if len(e.answers) == 0 {
		e.err = errReplayShort
		return inputlog.EnvCall{}, false
	}
	c := e.answers[0]
	if c.Kind != kind || c.Key != key {
		e.err = fmt.Errorf("runner: replay Env call %d/%x, recorded %d/%x", kind, key[:4], c.Kind, c.Key[:4])
		return inputlog.EnvCall{}, false
	}
	e.answers = e.answers[1:]
	e.used = append(e.used, c)
	return c, true
}

func (e *replayEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}

var errReplayValidators = errors.New("runner: recorded validator lookup failed")

func (e *replayEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	c, ok := e.pop(inputlog.EnvValidatorsAt, parent)
	if !ok {
		return nil, errReplayValidators
	}
	if c.Validators == nil {
		return nil, fmt.Errorf("%w: %s", errReplayValidators, c.Err)
	}
	return c.Validators, nil
}

func (e *replayEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	c, ok := e.pop(inputlog.EnvValidateProposal, codec.BlockHash(b.Header))
	if !ok {
		return 0, errReplayShort
	}
	return c.ProposalAnswer()
}

func (e *replayEnv) IsBadBlock(h types.Hash) bool {
	c, ok := e.pop(inputlog.EnvIsBadBlock, h)
	return ok && c.Bad
}

func (e *replayEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}

// startEnv answers the synthetic Start of a replay from a boundary record.
type startEnv struct {
	head *types.Header
	vs   *validator.Set
}

func (e *startEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}

func (e *startEnv) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	if e.vs == nil {
		return nil, errReplayValidators
	}
	return e.vs, nil
}

func (e *startEnv) ValidateProposal(*types.Block) (time.Duration, error) { return 0, errReplayShort }
func (e *startEnv) IsBadBlock(types.Hash) bool                           { return false }
func (e *startEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}
