package runner

import (
	"errors"
	"log/slog"
	"math"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
)

// These are local duration boundary values, not changes to a system clock,
// stored bytes, packet delivery or a running peer's environment.
func TestNormalRetryLogicalDeadlineBoundary(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		from := time.Duration(math.MaxInt64) - 2*time.Second
		if overflow {
			from++
		}
		clock := &manualClock{now: from}
		r := &Runner{cfg: Config{Core: consensus.Options{RoundChangeRetry: &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}}}, d: Deps{Clock: clock}, log: slog.New(slog.DiscardHandler)}
		r.timers = scheduler{clock: clock, wake: func() {}}
		arm := consensus.ArmTimer{Kind: consensus.RetryTimer, Duration: 2 * time.Second, Gen: 1, Retry: &consensus.RoundChangeRetryArm{MaxIntervalMs: 8000}}
		accepted := r.armTimer(arm, from)
		if overflow {
			if accepted || !errors.Is(r.Halted(), ErrHalted) || r.timers.live[consensus.RetryTimer] != nil || len(clock.q) != 0 {
				t.Fatal("overflow was installed or silently clamped")
			}
		} else {
			entry := r.timers.live[consensus.RetryTimer]
			if !accepted || r.Halted() != nil || entry == nil || entry.from+entry.arm.Duration != time.Duration(math.MaxInt64) {
				t.Fatal("representable boundary was rejected or changed")
			}
		}
		r.timers.clear()
	}
	clock := &manualClock{now: time.Duration(math.MaxInt64) - 2*time.Second + 1}
	r := &Runner{cfg: Config{Core: consensus.Options{RoundChangeRetry: &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}}}, d: Deps{Clock: clock}, log: slog.New(slog.DiscardHandler), core: consensus.NewState(consensus.Options{})}
	r.timers = scheduler{clock: clock, wake: func() {}}
	arm := &consensus.ArmTimer{Kind: consensus.RetryTimer, Duration: 2 * time.Second, Gen: 1, Retry: &consensus.RoundChangeRetryArm{MaxIntervalMs: 8000}}
	r.afterReplayTimers([]*consensus.ArmTimer{arm}, &consensus.Snapshot{})
	if !errors.Is(r.Halted(), ErrHalted) || r.timers.live[consensus.RetryTimer] != nil || len(clock.q) != 0 {
		t.Fatal("restore rearm installed an overflowing retry")
	}
}
