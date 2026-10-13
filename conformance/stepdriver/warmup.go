package stepdriver

import (
	"errors"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func warmupHeight(b *journal.StepRec) (uint64, error) {
	if !b.HeadNumber.IsUint64() || b.HeadNumber.Big().Uint64() == ^uint64(0) {
		return 0, ErrTraceWarmupUnavailable
	}
	return b.HeadNumber.Big().Uint64() + 1, nil
}

// bootstrapWarmup uses an explicit fresh state at the recorded head. It does
// not reconstruct backlog, prior views or unknown timer generations, and its
// initial outputs are neither executed nor yielded as a recorded step.
func bootstrapWarmup(opts consensus.Options, cfg *types.Config, blocks BlockSource, b *journal.StepRec) (*consensus.State, error) {
	head, err := headOf(blocks, b.HeadNumber, b.HeadHash)
	if err != nil {
		return nil, errors.Join(ErrTraceWarmupUnavailable, err)
	}
	env := &traceEnv{cfg: cfg, blocks: blocks, head: head}
	core := consensus.NewState(opts)
	_ = core.Step(env, consensus.Start{})
	if env.err != nil || !core.Running() || core.Snapshot().Validators == nil {
		return nil, ErrTraceWarmupUnavailable
	}
	return core, nil
}

func markWarmup(s *StepResult, b *journal.StepRec, w *TraceWarmup, approximate bool) error {
	s.Approximate = approximate
	if !approximate {
		return nil
	}
	height, err := warmupHeight(b)
	if err != nil {
		return &TraceError{Approximate: true, WriterRun: s.WriterRun, EngineRun: b.EngineRun, Step: b.Step, Err: err}
	}
	s.Warmup = height < w.CompareFromHeight
	return nil
}
