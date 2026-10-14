package manualclock_test

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/types"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestDeadlineOrderSameMomentAndCancellation(t *testing.T) {
	c := manualclock.New(time.Unix(100, 0))
	var got []string
	c.At(5*time.Second, func() { got = append(got, "first"); c.AfterFunc(0, func() { got = append(got, "nested") }) })
	c.At(5*time.Second, func() { got = append(got, "second") })
	gone := c.At(4*time.Second, func() { t.Fatal("cancelled callback fired") })
	if !gone.Stop() || gone.Stop() {
		t.Fatal("cancellation identity")
	}
	c.At(3*time.Second, func() {
		if c.Mono() != 3*time.Second {
			t.Fatal("callback did not run at its deadline")
		}
		got = append(got, "earlier")
	})
	c.AdvanceTo(9 * time.Second)
	if !reflect.DeepEqual(got, []string{"earlier", "first", "second", "nested"}) || c.Now() != time.Unix(109, 0) {
		t.Fatal(got, c.Now())
	}
	if _, ok := c.NextTime(); ok {
		t.Fatal("pending completed callback")
	}
}
func TestRunnerTimerQueueUsesEntryMomentAndKeepsQueuedExpiry(t *testing.T) {
	c := manualclock.New(time.Unix(0, 0))
	q := runner.NewTimerQueue(c)
	v := types.View{Sequence: types.HeightFromUint64(9), Round: types.RoundFromUint64(4)}
	msg := &consensus.Verified{Msg: &codec.Message{Code: codec.CodePreprepare, View: v}, Source: types.Address{3}}
	a := consensus.ArmTimer{Kind: consensus.FutureTimer, Duration: 5 * time.Second, Gen: 17, View: v, Round: types.RoundFromUint64(7), Msg: msg}
	c.AdvanceTo(2 * time.Second)
	q.Arm(a, time.Second) // entry=1s, completion=2s
	c.AdvanceTo(5 * time.Second)
	if q.Pending() {
		t.Fatal("timer fired before entry-based deadline")
	}
	c.AdvanceTo(6 * time.Second)
	q.Cancel(consensus.AllTimers)
	timeout, ok := q.Pop()
	if !ok || timeout.Kind != a.Kind || timeout.Gen != 17 || timeout.View != v || timeout.Round != a.Round || timeout.Msg != msg {
		t.Fatal("queued expiry or full context lost", timeout, ok)
	}
	if _, ok = q.Pop(); ok {
		t.Fatal("expiry consumed twice")
	}
	a.Gen = 18
	q.Arm(a, c.Mono())
	q.Cancel([]consensus.TimerKind{consensus.FutureTimer})
	c.AdvanceTo(20 * time.Second)
	if q.Pending() {
		t.Fatal("cancel-before-expiry still delivered")
	}
	a.Gen = 19
	q.Arm(a, c.Mono())
	a.Gen = 20
	q.Arm(a, c.Mono())
	c.AdvanceTo(25 * time.Second)
	timeout, ok = q.Pop()
	if !ok || timeout.Gen != 20 {
		t.Fatal("replacement reservation lost", timeout)
	}
	q.Clear()
	if q.Pending() {
		t.Fatal("clear left queued expiry")
	}
}

func TestManualClockRefusesBackwardOverflowAndReentrantAdvance(t *testing.T) {
	cases := []struct {
		name string
		run  func(*manualclock.Clock)
	}{
		{"backward", func(c *manualclock.Clock) { c.AdvanceTo(time.Second); c.AdvanceTo(0) }},
		{"overflow", func(c *manualclock.Clock) {
			c.AdvanceTo(time.Second)
			c.AfterFunc(time.Duration(math.MaxInt64), func() {})
		}},
		{"reentrant", func(c *manualclock.Clock) { c.At(0, func() { c.AdvanceTo(time.Second) }); c.AdvanceTo(0) }},
	}
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid advance accepted")
				}
			}()
			x.run(manualclock.New(time.Unix(0, 0)))
		})
	}
}
