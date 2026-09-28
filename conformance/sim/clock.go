package sim

import (
	"container/heap"
	"time"

	"github.com/0xmhha/wbft/consensus/runner"
)

// Epoch is the wall-clock time of simulated time 0.
var Epoch = time.Unix(1_700_000_000, 0).UTC()

// loop is the event queue of a simulation: callbacks ordered by time and,
// at equal times, by the order they were scheduled.
type loop struct {
	now time.Duration
	seq uint64
	q   eventHeap
}

type simEvent struct {
	at        time.Duration
	seq       uint64
	f         func()
	cancelled bool
	fired     bool
	idx       int
}

type eventHeap []*simEvent

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *eventHeap) Push(x any)   { e := x.(*simEvent); e.idx = len(*h); *h = append(*h, e) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}

// at schedules f at time t (not before now).
func (l *loop) at(t time.Duration, f func()) *simEvent {
	if t < l.now {
		t = l.now
	}
	l.seq++
	e := &simEvent{at: t, seq: l.seq, f: f}
	heap.Push(&l.q, e)
	return e
}

func (l *loop) after(d time.Duration, f func()) *simEvent {
	if d < 0 {
		d = 0
	}
	return l.at(l.now+d, f)
}

// nextTime returns the time of the next live event.
func (l *loop) nextTime() (time.Duration, bool) {
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
func (l *loop) runAt(t time.Duration) {
	l.now = t
	for l.q.Len() > 0 && l.q[0].at == t {
		e := heap.Pop(&l.q).(*simEvent)
		if e.cancelled {
			continue
		}
		e.fired = true
		e.f()
	}
}

// nodeClock is the clock of one node incarnation: simulated time plus the
// node's skew; timers of a crashed incarnation never fire.
type nodeClock struct {
	l    *loop
	skew time.Duration
	live func() bool
}

type simTimer struct{ e *simEvent }

func (t simTimer) Stop() bool {
	if t.e.fired || t.e.cancelled {
		return false
	}
	t.e.cancelled = true
	return true
}

func (c *nodeClock) Now() time.Time      { return Epoch.Add(c.l.now + c.skew) }
func (c *nodeClock) Mono() time.Duration { return c.l.now }
func (c *nodeClock) AfterFunc(d time.Duration, f func()) runner.Timer {
	live := c.live
	return simTimer{c.l.after(d, func() {
		if live() {
			f()
		}
	})}
}
