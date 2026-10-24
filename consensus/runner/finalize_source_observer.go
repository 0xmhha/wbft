package runner

import (
	"bytes"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// FinalizeSourceObserver receives detached call-boundary metadata after all
// source/commit/application mutexes are released. Calls may arrive out of order;
// Sequence retains instrumentation order. Observers must return promptly. This
// hook does not execute or authenticate the application, or enable cache replay.
type FinalizeSourceObserver interface{ ObserveFinalizeSource(journal.FinalizeRec) }

type finalizeSourceOwner struct{ engine, step, output, task uint64 }

// SourceFinalizer is an optional application bridge for original task ownership.
// The ordinary App and manual completion contracts remain unchanged. A bridge
// must preserve the original request and context, including cancellation.
type SourceFinalizer interface {
	FinalizeBlockWithSource(*types.Block, types.Round, app.FinalizeSource) error
}

func (r *Runner) callFinalize(j commitJob) error {
	if r.d.FinalizeSources != nil {
		if target, ok := r.d.App.(SourceFinalizer); ok {
			s := j.source
			return target.FinalizeBlockWithSource(j.block, j.round, app.FinalizeSource{
				Run: r.finalizeNamespace, Engine: s.engine, Step: s.step, Output: s.output, Task: s.task,
			})
		}
	}
	return r.d.App.FinalizeBlock(j.block, j.round)
}

// finalizeSource records a measured boundary without consulting the currently
// running engine. Only enqueue establishes the original immutable task owner.
func (r *Runner) finalizeSource(action string, j commitJob, before, after int, hasError bool, queueRun string, queue *journal.AppQueueRec) *journal.FinalizeRec {
	if r.d.FinalizeSources == nil {
		return nil
	}
	var arguments []byte
	var encodingError bool
	if action == "enqueue" || action == "enter" {
		var err error
		arguments, err = inputlog.EncodeOutputs([]consensus.Output{consensus.Commit{Block: j.block, Round: j.round}})
		encodingError = err != nil
	}
	r.finalizeSourceMu.Lock()
	defer r.finalizeSourceMu.Unlock()
	if r.finalizeSourceSequence == ^uint64(0) {
		r.finalizeSourceExhausted = true
	} else if !r.finalizeSourceExhausted {
		r.finalizeSourceSequence++
	}
	s := j.source
	rec := &journal.FinalizeRec{Version: journal.FinalizeSourceVersion, Sequence: r.finalizeSourceSequence, Task: s.task, EngineRun: s.engine, Step: s.step, Output: s.output, Action: action, Before: uint64(before), After: uint64(after), Arguments: arguments, HasError: hasError, Mono: r.d.Clock.Mono(), WallNs: r.d.Clock.Now().UnixNano()}
	if action == "enqueue" {
		rec.Task = rec.Sequence
	}
	if s.engine == 0 || s.step == 0 || s.output == 0 || rec.Task == 0 {
		rec.Unavailable = "owner_unavailable"
	}
	if encodingError {
		rec.Arguments, rec.Unavailable = nil, "argument_encoding"
	}
	if action == "notify" {
		if queueRun == "" || queue == nil || queue.Request == 0 || queue.Unavailable != "" {
			rec.Unavailable = "queue_source_unavailable"
		} else {
			rec.QueueRun, rec.QueueRequest = queueRun, queue.Request
			// Reuse the actual encoded append; never call Error.Error again.
			rec.Input = bytes.Clone(queue.Input)
		}
	}
	if r.finalizeSourceExhausted {
		rec.Sequence, rec.Unavailable = 0, "metadata_exhausted"
		if action == "enqueue" {
			rec.Task = 0
		}
	}
	return rec
}

func (r *Runner) finalizeQueueRun() string {
	if r.d.FinalizeSources != nil {
		if source, ok := r.d.AppQueueSources.(interface{ CaptureRun() string }); ok {
			return source.CaptureRun()
		}
	}
	return ""
}

func (r *Runner) publishFinalize(rec *journal.FinalizeRec) {
	if rec != nil {
		r.d.FinalizeSources.ObserveFinalizeSource(*rec)
	}
}
