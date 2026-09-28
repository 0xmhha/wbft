package stepdriver

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// BlockSource answers Head and ValidatorsAt of a trace replay from
// recorded block data.
type BlockSource interface {
	HeaderByNumber(n types.Height) (*types.Header, error)
	BlockByHash(h types.Hash) (*types.Block, error)
}

// JournalReader yields the records of a message journal in order;
// *journal.Reader is one.
type JournalReader interface {
	Next() (journal.Record, error)
}

// TraceOptions configure RunTrace.
type TraceOptions struct {
	Blocks BlockSource
	// FromStep and ToStep limit the reported steps of every engine run
	// (0: from the start, to the end); every step is still fed.
	FromStep uint64
	ToStep   uint64
	// WithVars includes consensus.Vars after every step.
	WithVars bool
}

// StepResult is one replayed core Step.
type StepResult struct {
	EngineRun uint64
	Step      uint64
	Input     consensus.Input
	// EnvCalls are the Env calls the core made, with the answers given.
	EnvCalls  []inputlog.EnvCall
	Outputs   []consensus.Output
	OutDigest types.Hash
	// Match reports that OutDigest equals the recorded out_digest and the
	// validator set digest equals the recorded one.
	Match bool
	Vars  *consensus.Vars
}

// Errors of RunTrace.
var (
	ErrTraceNoSegment = errors.New("stepdriver: journal has no segment record before its steps")
	ErrTraceGap       = errors.New("stepdriver: journal steps are not contiguous")
)

// RunTrace rebuilds consensus.State from the journal "segment" record and
// feeds the recorded steps in order: every "start" step creates a new core
// (with the timer generations the step records). Head and ValidatorsAt are
// answered from opts.Blocks, ValidateProposal and IsBadBlock from the
// answers the step records, CommitHeader by header.CommitHeader. yield is
// called for every step within [FromStep, ToStep].
func RunTrace(j JournalReader, opts TraceOptions, yield func(StepResult) error) error {
	var cfg *types.Config
	var copts consensus.Options
	var core *consensus.State
	var run, last uint64
	for {
		rec, err := j.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			if cfg == nil {
				c, err := types.ParseChainConfig(b.Core.ChainConfig)
				if err != nil {
					return fmt.Errorf("stepdriver: segment chain configuration: %w", err)
				}
				cfg = c
				copts = consensus.Options{Config: cfg, Self: b.Core.Self, Improvements: consensus.ImprovementSet(b.Core.Improvements),
					BacklogLimit: int(b.Core.BacklogLimit)}
			}
		case *journal.StepRec:
			if cfg == nil {
				return ErrTraceNoSegment
			}
			if b.InputKind == inputlog.KindStart {
				core = consensus.NewState(copts)
				var g [3]uint64
				copy(g[:], b.TimerGens)
				core.RestoreTimerGens(g)
				run, last = b.EngineRun, b.Step-1
			}
			if core == nil {
				// Steps of an engine run whose start is not in the journal
				// (pruned or lost) cannot be replayed.
				continue
			}
			if b.EngineRun != run || b.Step != last+1 {
				return fmt.Errorf("%w: engine run %d step %d after run %d step %d", ErrTraceGap, b.EngineRun, b.Step, run, last)
			}
			last = b.Step
			res, err := replayStep(core, cfg, opts.Blocks, b)
			if err != nil {
				return fmt.Errorf("stepdriver: engine run %d step %d: %w", b.EngineRun, b.Step, err)
			}
			if opts.WithVars {
				res.Vars = core.Vars()
			}
			if b.Step < opts.FromStep || opts.ToStep != 0 && b.Step > opts.ToStep {
				continue
			}
			if err := yield(res); err != nil {
				return err
			}
		}
	}
}

// replayStep feeds one recorded step to core.
func replayStep(core *consensus.State, cfg *types.Config, blocks BlockSource, b *journal.StepRec) (StepResult, error) {
	in, err := inputlog.Decode(b.InputKind, b.Input, nil)
	if err != nil {
		return StepResult{}, err
	}
	env := &traceEnv{cfg: cfg, blocks: blocks}
	if nh, ok := in.(consensus.NewHead); ok && nh.Header != nil {
		env.head = nh.Header
	} else if env.head, err = headOf(blocks, b.HeadNumber, b.HeadHash); err != nil {
		return StepResult{}, err
	}
	for _, e := range b.Env {
		c, err := inputlog.DecodeEnv(e)
		if err != nil {
			return StepResult{}, err
		}
		env.answers = append(env.answers, c)
	}
	outs := core.Step(env, in)
	if env.err != nil {
		return StepResult{}, env.err
	}
	d, err := inputlog.OutDigest(outs)
	if err != nil {
		return StepResult{}, err
	}
	vd := consensus.ValsetDigest(core.Snapshot().Validators)
	return StepResult{EngineRun: b.EngineRun, Step: b.Step, Input: in, EnvCalls: env.calls, Outputs: outs, OutDigest: d,
		Match: d == b.OutDigest && vd == b.ValsetDigest}, nil
}

func headOf(blocks BlockSource, n types.Height, h types.Hash) (*types.Header, error) {
	if blocks == nil {
		return nil, errors.New("no block source")
	}
	hd, err := blocks.HeaderByNumber(n)
	if err == nil && codec.BlockHash(hd) == h {
		return hd, nil
	}
	b, err := blocks.BlockByHash(h)
	if err != nil {
		return nil, fmt.Errorf("head %s %x: %w", n, h[:4], err)
	}
	return b.Header, nil
}

// traceEnv answers a replayed step.
type traceEnv struct {
	cfg     *types.Config
	blocks  BlockSource
	head    *types.Header
	answers []inputlog.EnvCall
	calls   []inputlog.EnvCall
	err     error
}

func (e *traceEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}

func (e *traceEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	vs, err := validator.ValidatorsAt(chainOf{e.blocks}, e.cfg, n, parent, nil)
	c := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: n, Key: parent, Validators: vs}
	if err != nil {
		c.Validators, c.Err = nil, err.Error()
	}
	e.calls = append(e.calls, c)
	return vs, err
}

func (e *traceEnv) pop(kind uint8, key types.Hash) (inputlog.EnvCall, bool) {
	if e.err != nil {
		return inputlog.EnvCall{}, false
	}
	if len(e.answers) == 0 || e.answers[0].Kind != kind || e.answers[0].Key != key {
		e.err = fmt.Errorf("the journal holds no answer for Env call %d on %x", kind, key[:4])
		return inputlog.EnvCall{}, false
	}
	c := e.answers[0]
	e.answers = e.answers[1:]
	e.calls = append(e.calls, c)
	return c, true
}

func (e *traceEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	c, ok := e.pop(inputlog.EnvValidateProposal, codec.BlockHash(b.Header))
	if !ok {
		return 0, errors.New("stepdriver: no recorded proposal answer")
	}
	return c.ProposalAnswer()
}

func (e *traceEnv) IsBadBlock(h types.Hash) bool {
	c, ok := e.pop(inputlog.EnvIsBadBlock, h)
	return ok && c.Bad
}

func (e *traceEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}

// chainOf is a types.ChainReader over a BlockSource.
type chainOf struct{ b BlockSource }

func heightOf(idx uint64) types.Height { return types.HeightFromUint64(idx) }

func (c chainOf) Head() *types.Header { return nil }
func (c chainOf) HeaderByNumber(idx uint64) *types.Header {
	if c.b == nil {
		return nil
	}
	h, err := c.b.HeaderByNumber(heightOf(idx))
	if err != nil {
		return nil
	}
	return h
}
func (c chainOf) Header(hash types.Hash, idx uint64) *types.Header {
	h := c.HeaderByHash(hash)
	if h == nil || !h.Number.IsUint64() || h.Number.CmpUint64(idx) != 0 {
		return nil
	}
	return h
}
func (c chainOf) HeaderByHash(hash types.Hash) *types.Header {
	if c.b == nil {
		return nil
	}
	b, err := c.b.BlockByHash(hash)
	if err != nil {
		return nil
	}
	return b.Header
}
func (c chainOf) HasBlock(hash types.Hash, idx uint64) bool { return c.Header(hash, idx) != nil }
