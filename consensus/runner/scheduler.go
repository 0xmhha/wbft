package runner

import (
	"sync"

	"github.com/0xmhha/wbft/consensus"
)

// scheduler holds one armed timer per kind and the queue of expiries. An
// expiry is queued when the timer fires; cancelling a timer that has not
// fired drops it, and an expiry already queued stays queued (the core
// decides what a late expiry does, by its generation).
type scheduler struct {
	r     *Runner
	mu    sync.Mutex // runner.timers.mu
	live  [3]*timerEntry
	fired []consensus.Timeout
}

type timerEntry struct {
	t    Timer
	arm  consensus.ArmTimer
	done bool
}

// arm arms a timer, cancelling the armed timer of the same kind.
func (s *scheduler) arm(a consensus.ArmTimer) {
	e := &timerEntry{arm: a}
	s.mu.Lock()
	if old := s.live[a.Kind]; old != nil {
		old.done = true
		old.t.Stop()
	}
	s.live[a.Kind] = e
	s.mu.Unlock()
	t := s.r.d.Clock.AfterFunc(a.Duration, func() { s.fire(e) })
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
	s.mu.Unlock()
	s.r.wake()
}

// cancel cancels the armed timers of the given kinds and returns them.
func (s *scheduler) cancel(kinds []consensus.TimerKind) []consensus.ArmTimer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []consensus.ArmTimer
	for _, k := range kinds {
		if e := s.live[k]; e != nil {
			e.done = true
			if e.t != nil {
				e.t.Stop()
			}
			s.live[k] = nil
			out = append(out, e.arm)
		}
	}
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
	return t, true
}

// clear cancels every timer and drops the queued expiries.
func (s *scheduler) clear() {
	s.cancel(consensus.AllTimers)
	s.mu.Lock()
	s.fired = nil
	s.mu.Unlock()
}
