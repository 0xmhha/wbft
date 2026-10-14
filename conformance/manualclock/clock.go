// Package manualclock provides the deterministic event queue shared by
// WBFT simulation and recorded-input experiments. It does not run consensus.
package manualclock

import (
	"container/heap"
	"math"
	"time"

	"github.com/0xmhha/wbft/consensus/runner"
)

// Clock is a single-threaded manual clock with callbacks ordered by deadline
// and, at equal deadlines, by insertion order. Its zero value is usable.
type Clock struct {
	now         time.Duration
	seq         uint64
	q           eventHeap
	base        time.Time
	initialized bool
	advancing   bool
}

// Event is an opaque cancellable callback reservation.
type Event struct {
	at        time.Duration
	seq       uint64
	f         func()
	cancelled bool
	fired     bool
	idx       int
}

type eventHeap []*Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *eventHeap) Push(x any)   { e := x.(*Event); e.idx = len(*h); *h = append(*h, e) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}

// At schedules f at time t (not before now).
func (l *Clock) At(t time.Duration, f func()) *Event {
	if t < l.now {
		t = l.now
	}
	l.seq++
	e := &Event{at: t, seq: l.seq, f: f}
	heap.Push(&l.q, e)
	return e
}

func (l *Clock) after(d time.Duration, f func()) *Event {
	if d < 0 {
		d = 0
	}
	if d > time.Duration(math.MaxInt64)-l.now {
		panic("manualclock: deadline overflow")
	}
	return l.At(l.now+d, f)
}

// NextTime returns the time of the next live event.
func (l *Clock) NextTime() (time.Duration, bool) {
	for l.q.Len() > 0 {
		e := l.q[0]
		if !e.cancelled {
			return e.at, true
		}
		heap.Pop(&l.q)
	}
	return 0, false
}

// runAt runs every live event scheduled at time t, including those that
// they schedule at t.
func (l *Clock) runAt(t time.Duration) {
	l.now = t
	for l.q.Len() > 0 && l.q[0].at == t {
		e := heap.Pop(&l.q).(*Event)
		if e.cancelled {
			continue
		}
		e.fired = true
		e.f()
	}
}

// New sets the wall-clock instant corresponding to monotonic time zero.
func New(base time.Time) *Clock      { return &Clock{base: base, initialized: true} }
func (l *Clock) Mono() time.Duration { return l.now }
func (l *Clock) Now() time.Time {
	base := l.base
	if !l.initialized {
		base = time.Unix(0, 0)
	}
	return base.Add(l.now)
}
func (l *Clock) AfterFunc(d time.Duration, f func()) runner.Timer { return l.after(d, f) }
func (e *Event) Stop() bool {
	if e.fired || e.cancelled {
		return false
	}
	e.cancelled = true
	return true
}

// AdvanceTo delivers callbacks at their own deadlines, including callbacks
// scheduled for the same instant during delivery. Time never moves backwards.
func (l *Clock) AdvanceTo(t time.Duration) {
	if l.advancing {
		panic("manualclock: reentrant advance")
	}
	if t < l.now {
		panic("manualclock: time moved backwards")
	}
	l.advancing = true
	defer func() { l.advancing = false }()
	for {
		next, ok := l.NextTime()
		if !ok || next > t {
			break
		}
		l.runAt(next)
	}
	l.now = t
}
