// Package buildqueue models a serial application worker with one latest pending
// request. Selection is explicit: simultaneous timer, Done, stop and queue events
// must be ordered by the driving scheduler rather than guessed from timestamps.
package buildqueue

import (
	"errors"
	"time"

	"github.com/0xmhha/wbft/app"
)

var ErrTransition = errors.New("buildqueue: invalid transition")

type Request struct {
	ID   string
	Wait time.Duration
}
type Phase uint8

const (
	Idle Phase = iota
	Waiting
	CheckingHead
	Assembling
)

type Kind uint8

const (
	ArmWait Kind = iota
	CheckHead
	AssemblyStarted
	CancelAssembly
	Finished
)

type Effect struct {
	ID     string
	Kind   Kind
	Wait   time.Duration
	Status app.BuildStatus
}
type Choice uint8

const (
	TimerReady Choice = iota
	HeightLeft
	WorkerStopped
	NewerRequest
)

// Queue is a single-threaded transition model. The caller serializes all
// inputs and records its selection order; no goroutine arbitration is implied.
type Queue struct {
	active, pending    *Request
	phase              Phase
	stopped, cancelled bool
	seen               map[string]bool
}

func New() *Queue              { return &Queue{seen: map[string]bool{}} }
func (q *Queue) Phase() Phase  { return q.phase }
func (q *Queue) Stopped() bool { return q.stopped }
func (q *Queue) Pending() bool { return q.pending != nil }
func (q *Queue) ActiveID() string {
	if q.active == nil {
		return ""
	}
	return q.active.ID
}

// Offer can replace a queued request even while the worker is stopped. It never
// interrupts assembly; a waiting worker consumes the queue through Choose.
func (q *Queue) Offer(r Request) ([]Effect, error) {
	if r.ID == "" || r.Wait < 0 || q.seen[r.ID] {
		return nil, ErrTransition
	}
	q.seen[r.ID] = true
	out := []Effect{}
	if q.pending != nil {
		out = append(out, Effect{ID: q.pending.ID, Kind: Finished, Status: app.BuildReplaced})
	}
	q.pending = &r
	return out, nil
}

// Select consumes one request and checks availability before any timer wait.
func (q *Queue) Select(available bool) ([]Effect, error) {
	if q.stopped || q.active != nil || q.pending == nil {
		return nil, ErrTransition
	}
	q.active, q.pending = q.pending, nil
	q.cancelled = false
	if !available {
		return q.finish(app.BuildUnavailable), nil
	}
	if q.active.Wait > 0 {
		q.phase = Waiting
		return []Effect{{ID: q.active.ID, Kind: ArmWait, Wait: q.active.Wait}}, nil
	}
	q.phase = CheckingHead
	return []Effect{{ID: q.active.ID, Kind: CheckHead}}, nil
}
func (q *Queue) Choose(id string, choice Choice) ([]Effect, error) {
	if q.active == nil || q.active.ID != id || q.phase != Waiting {
		return nil, ErrTransition
	}
	switch choice {
	case TimerReady:
		q.phase = CheckingHead
		return []Effect{{ID: id, Kind: CheckHead}}, nil
	case HeightLeft:
		return q.finish(app.BuildHeightLeft), nil
	case WorkerStopped:
		q.stopped = true
		return q.finish(app.BuildStopped), nil
	case NewerRequest:
		if q.pending == nil {
			return nil, ErrTransition
		}
		return q.finish(app.BuildReplaced), nil
	default:
		return nil, ErrTransition
	}
}
func (q *Queue) Head(id string, matches bool) ([]Effect, error) {
	if q.active == nil || q.active.ID != id || q.phase != CheckingHead {
		return nil, ErrTransition
	}
	if !matches {
		return q.finish(app.BuildHeadChanged), nil
	}
	q.phase = Assembling
	return []Effect{{ID: id, Kind: AssemblyStarted}}, nil
}

// Done cancels the executor context during assembly but does not release the
// serial worker. Only the actual executor return can complete that request.
func (q *Queue) Done(id string) ([]Effect, error) {
	if q.active == nil || q.active.ID != id {
		return nil, ErrTransition
	}
	if q.phase == Waiting {
		return q.Choose(id, HeightLeft)
	}
	if q.phase != Assembling {
		return nil, ErrTransition
	}
	if q.cancelled {
		return []Effect{}, nil
	}
	q.cancelled = true
	return []Effect{{ID: id, Kind: CancelAssembly}}, nil
}

// Stop is not executor-context cancellation. In-flight assembly keeps ownership
// until Complete; queued work remains for an explicit subsequent Start.
func (q *Queue) Stop() []Effect {
	q.stopped = true
	if q.phase == Waiting && q.active != nil {
		return q.finish(app.BuildStopped)
	}
	return []Effect{}
}
func (q *Queue) Start() error {
	if q.stopped && q.active != nil {
		return ErrTransition
	}
	q.stopped = false
	return nil
}
func (q *Queue) Complete(id string, status app.BuildStatus) ([]Effect, error) {
	if q.active == nil || q.active.ID != id || q.phase != Assembling || status != app.BuildSubmitted && status != app.BuildFailed {
		return nil, ErrTransition
	}
	return q.finish(status), nil
}
func (q *Queue) finish(status app.BuildStatus) []Effect {
	out := []Effect{{ID: q.active.ID, Kind: Finished, Status: status}}
	q.active = nil
	q.phase = Idle
	q.cancelled = false
	return out
}
