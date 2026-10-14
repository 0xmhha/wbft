package sim

import (
	"time"

	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus/runner"
)

// Epoch is the wall-clock time of simulated time 0.
var Epoch = time.Unix(1_700_000_000, 0).UTC()

// loop uses the shared deterministic callback scheduler.
type loop struct{ c manualclock.Clock }

func (l *loop) at(t time.Duration, f func()) *manualclock.Event { return l.c.At(t, f) }
func (l *loop) after(d time.Duration, f func()) runner.Timer    { return l.c.AfterFunc(d, f) }
func (l *loop) nextTime() (time.Duration, bool)                 { return l.c.NextTime() }
func (l *loop) runAt(t time.Duration)                           { l.c.AdvanceTo(t) }

// nodeClock is the clock of one node incarnation: simulated time plus the
// node's skew; timers of a crashed incarnation never fire.
type nodeClock struct {
	l    *loop
	skew time.Duration
	live func() bool
}

func (c *nodeClock) Now() time.Time      { return Epoch.Add(c.l.c.Mono() + c.skew) }
func (c *nodeClock) Mono() time.Duration { return c.l.c.Mono() }
func (c *nodeClock) AfterFunc(d time.Duration, f func()) runner.Timer {
	live := c.live
	return c.l.after(d, func() {
		if live() {
			f()
		}
	})
}
