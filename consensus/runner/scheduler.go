package runner

import (
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"sync"
	"time"

	"github.com/0xmhha/wbft/consensus"
)

// scheduler holds one armed timer per kind and the queue of expiries. An
// expiry is queued when the timer fires; cancelling a timer that has not
// fired drops it, and an expiry already queued stays queued (the core
// decides what a late expiry does, by its generation).
type scheduler struct {
	clock    Clock
	wake     func()
	mu       sync.Mutex // runner.timers.mu
	live     [3]*timerEntry
	fired    []consensus.Timeout
	queued   []*timerEntry
	owner    timerOwner
	sequence uint64
	trace    func(*journal.TimerRec)
}

type timerOwner struct {
	engine, step, output uint64
	source               string
}

type timerEntry struct {
	owner timerOwner
	from  time.Duration
	input []byte
	t     Timer
	arm   consensus.ArmTimer
	done  bool
}

// arm arms a timer, cancelling the armed timer of the same kind. The
// timer runs from the monotonic moment from (the start of the step that
// armed it), so the time spent in the step before arming counts.
func (s *scheduler) arm(a consensus.ArmTimer, from time.Duration) {
	e := &timerEntry{arm: a, from: from}
	if s.trace != nil {
		e.input, _ = inputlog.Encode(consensus.Timeout{Kind: a.Kind, View: a.View, Round: a.Round, Gen: a.Gen, Msg: a.Msg})
	}
	s.mu.Lock()
	e.owner = s.owner
	if old := s.live[a.Kind]; old != nil {
		old.done = true
		if old.t != nil {
			old.t.Stop()
		}
		s.record("replace", s.owner, old)
	}
	s.live[a.Kind] = e
	s.record("arm", s.owner, e)
	s.mu.Unlock()
	t := s.clock.AfterFunc(max(a.Duration-(s.clock.Mono()-from), 0), func() { s.fire(e) })
	s.mu.Lock()
	e.t = t
	s.mu.Unlock()
}

func (s *scheduler) fire(e *timerEntry) {
	s.mu.Lock()
	if e.done {
		s.mu.Unlock()
		return
	}
	e.done = true
	if s.live[e.arm.Kind] == e {
		s.live[e.arm.Kind] = nil
	}
	a := e.arm
	s.fired = append(s.fired, consensus.Timeout{Kind: a.Kind, View: a.View, Round: a.Round, Gen: a.Gen, Msg: a.Msg})
	s.queued = append(s.queued, e)
	s.record("queued", e.owner, e)
	s.mu.Unlock()
	if s.wake != nil {
		s.wake()
	}
}

// cancel cancels the armed timers of the given kinds and returns them.
func (s *scheduler) cancel(kinds []consensus.TimerKind) []consensus.ArmTimer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []consensus.ArmTimer
	var cancelled []*timerEntry
	for _, k := range kinds {
		if e := s.live[k]; e != nil {
			e.done = true
			if e.t != nil {
				e.t.Stop()
			}
			s.live[k] = nil
			cancelled = append(cancelled, e)
			out = append(out, e.arm)
		}
	}
	for _, e := range cancelled {
		s.record("cancelled", s.owner, e)
	}
	s.record("cancel", s.owner, nil, kinds...)
	return out
}

func (s *scheduler) pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.fired) > 0
}

func (s *scheduler) pop() (consensus.Timeout, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.fired) == 0 {
		return consensus.Timeout{}, false
	}
	t := s.fired[0]
	s.fired = s.fired[1:]
	if len(s.queued) > 0 {
		s.record("pop", s.owner, s.queued[0])
		s.queued = s.queued[1:]
	}
	return t, true
}

// clear cancels every timer and drops the queued expiries.
func (s *scheduler) clear() {
	s.cancel(consensus.AllTimers)
	s.mu.Lock()
	s.fired = nil
	s.queued = nil
	s.record("clear", s.owner, nil)
	s.mu.Unlock()
}

// TimerQueue uses the runner's timer reservation and expiry implementation.
// It preserves full timeout context and already-queued expiries after cancel.
// Arm and cancel calls are serialized by the execution owner; clock expiry
// callbacks may run concurrently with that owner.
type TimerQueue struct{ s scheduler }

func NewTimerQueue(clock Clock) *TimerQueue {
	if clock == nil {
		panic("runner: timer queue needs a clock")
	}
	return &TimerQueue{s: scheduler{clock: clock}}
}
func (q *TimerQueue) Arm(a consensus.ArmTimer, from time.Duration) { q.s.arm(a, from) }
func (q *TimerQueue) Cancel(kinds []consensus.TimerKind) []consensus.ArmTimer {
	return q.s.cancel(kinds)
}
func (q *TimerQueue) Pending() bool                  { return q.s.pending() }
func (q *TimerQueue) Pop() (consensus.Timeout, bool) { return q.s.pop() }
func (q *TimerQueue) Clear()                         { q.s.clear() }

// setOwner is called only by the execution owner, before an operation. Timer
// callbacks use the immutable owner captured when the timer was armed.
func (s *scheduler) setOwner(engine, step, output uint64, source string) {
	s.mu.Lock()
	s.owner = timerOwner{engine, step, output, source}
	s.mu.Unlock()
}

// record is called with mu held, after the mutation. It measures operation
// order rather than attributing a callback to the currently executing step.
func (s *scheduler) record(action string, owner timerOwner, e *timerEntry, kinds ...consensus.TimerKind) {
	if s.trace == nil {
		return
	}
	s.sequence++
	wall := s.clock.Now()
	mono := s.clock.Mono()
	rec := &journal.TimerRec{Sequence: s.sequence, EngineRun: owner.engine, Step: owner.step, Output: owner.output, Source: owner.source, Action: action, Mono: mono, WallNs: wall.UnixNano()}
	for _, kind := range kinds {
		rec.Kinds = append(rec.Kinds, uint64(kind))
	}
	if e != nil {
		rec.ArmEngineRun = e.owner.engine
		rec.ArmStep = e.owner.step
		rec.ArmOutput = e.owner.output
		rec.EntryMono = e.from
		rec.Deadline = e.from + e.arm.Duration
		rec.Input = e.input
	}
	s.trace(rec)
}
