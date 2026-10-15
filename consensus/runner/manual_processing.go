package runner

import (
	"errors"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
)

var ErrProcessingPending = errors.New("runner: manual core service pending")

// ProcessingWork identifies a reserved receive check or core input. Code is
// nonzero only for a wire message. Kind uses the inputlog kind vocabulary.
type ProcessingWork struct {
	Phase string
	Kind  string
	Code  uint64
}

const (
	ProcessingCheck = "receive_check"
	ProcessingCore  = "core_input"
)

// ManualProcessing reserves work, occupies its worker for Delay, then executes
// the existing atomic operation at completion. This is a declared pre-dispatch
// service approximation, not a claim about an operation's internal milestones.
// Schedule must serialize callbacks with Pump on the manual driver's goroutine;
// it must not invoke a positive-delay callback inline. Engine controls wait
// behind reserved core work; receive checks have independent worker capacity.
type ManualProcessing struct {
	Delay    func(ProcessingWork) time.Duration
	Schedule func(time.Duration, func())
}

// ProcessingPending reports core work reserved by the manual driver. Like
// Pump and Vars, callers must serialize this with the manual scheduler.
func (r *Runner) ProcessingPending() bool { return r.manualStepPending }

func (r *Runner) serviceDelay(work ProcessingWork) time.Duration {
	d := r.d.ManualProcessing.Delay(work)
	if d < 0 {
		r.halt(errors.New("negative manual processing delay"))
	}
	return d
}

func (r *Runner) deferManualStep(q queued) bool {
	if r.d.ManualProcessing == nil {
		return false
	}
	work := ProcessingWork{Phase: ProcessingCore, Kind: inputlog.Kind(q.in)}
	if m, ok := q.in.(consensus.Message); ok {
		work.Code = uint64(m.Code)
	}
	d := r.serviceDelay(work)
	if d <= 0 {
		return d < 0
	}
	r.manualStepPending = true
	generation := r.engineRun
	completed := false
	r.d.ManualProcessing.Schedule(d, func() {
		if completed {
			return
		}
		completed = true
		if !r.running.Load() || r.engineRun != generation {
			return
		}
		r.manualStepPending = false
		if r.Halted() == nil {
			r.handle(q)
		}
	})
	return true
}

func (r *Runner) deferManualCheck(in transport.Inbound) bool {
	if r.d.ManualProcessing == nil {
		return false
	}
	d := r.serviceDelay(ProcessingWork{Phase: ProcessingCheck, Kind: inputlog.KindMessage, Code: in.Code})
	if d <= 0 {
		return d < 0
	}
	r.manualChecks++
	generation := r.engineRun
	completed := false
	r.d.ManualProcessing.Schedule(d, func() {
		if completed {
			return
		}
		completed = true
		if r.engineRun != generation {
			return
		}
		r.manualChecks--
		if r.running.Load() && r.Halted() == nil {
			r.inbox.check(in)
		}
	})
	return true
}

func (r *Runner) pumpProcessing() bool {
	did := false
	for {
		progressed := false
		for r.inbox.checkOne(true) {
			progressed = true
		}
		if !r.manualCommitPending.Load() && !r.manualStepPending {
			if r.processOne() {
				progressed = true
			}
			if !r.manualStepPending && r.commitOne() {
				progressed = true
			}
		}
		if !progressed {
			return did
		}
		did = true
	}
}
