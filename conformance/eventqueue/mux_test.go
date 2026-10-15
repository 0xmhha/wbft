package eventqueue

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type driver struct{ t *testing.T }

func (d driver) ok(effects []Effect, err error) []Effect {
	d.t.Helper()
	if err != nil {
		d.t.Fatal(err)
	}
	return effects
}
func (d driver) blocked(effects []Effect, err error) {
	d.t.Helper()
	if !errors.Is(err, ErrNotReady) || len(effects) != 0 {
		d.t.Fatal("expected a blocked operation", effects, err)
	}
}
func (d driver) invalid(effects []Effect, err error) {
	d.t.Helper()
	if !errors.Is(err, ErrTransition) || len(effects) != 0 {
		d.t.Fatal("expected an invalid transition", effects, err)
	}
}

func stamp(n int64) time.Time { return time.Unix(0, n) }

func TestIndependentPostsOvertakeButOnePostRetainsSubscriberOrder(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("first", stamp(0), "request"))
	d.ok(m.Subscribe("second", stamp(0), "request"))
	d.ok(m.Call(Event{ID: "old", Kind: "request", Stamp: stamp(1)}))
	d.ok(m.Snapshot("old"))
	d.ok(m.Call(Event{ID: "new", Kind: "request", Stamp: stamp(2)}))
	d.ok(m.Snapshot("new"))
	var deliveries []string
	for _, id := range []string{"new", "old"} {
		for _, sub := range []string{"first", "second"} {
			d.ok(m.Enter(id))
			effects := d.ok(m.Receive(id))
			if effects[0].Subscription != sub {
				t.Fatal("post changed snapshot order", effects)
			}
			deliveries = append(deliveries, id+":"+sub)
			// A receive still owns the lock and cannot visit the next subscriber.
			d.invalid(m.Enter(id))
			d.invalid(m.Return(id))
			d.ok(m.Release(id))
		}
		d.ok(m.Return(id))
	}
	if !reflect.DeepEqual(deliveries, []string{"new:first", "new:second", "old:first", "old:second"}) {
		t.Fatal(deliveries)
	}
	old, _ := m.Post("old")
	newer, _ := m.Post("new")
	if !old.Event.Stamp.Before(newer.Event.Stamp) || old.Rejected || newer.Rejected {
		t.Fatal("delivery reordered or rejected the original timestamps", old, newer)
	}
}

func TestSnapshotRetainsRemovedInstanceAndExcludesLaterSubscription(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("old-run", stamp(0), "request"))
	d.ok(m.Call(Event{ID: "post", Kind: "request", Stamp: stamp(1)}))
	d.ok(m.Snapshot("post"))
	d.ok(m.Subscribe("new-run", stamp(2), "request"))
	d.ok(m.Remove("old-run"))
	d.ok(m.SignalClose("old-run"))
	d.ok(m.BeginJoin("old-run"))
	d.ok(m.FinishClose("old-run"))
	d.ok(m.Enter("post"))
	d.blocked(m.Receive("post"))
	d.ok(m.Drop("post"))
	d.ok(m.Release("post"))
	d.ok(m.Return("post"))
	p, _ := m.Post("post")
	if !reflect.DeepEqual(p.Subscriptions, []string{"old-run"}) || p.Rejected {
		t.Fatal("accepted post was redirected or rejected", p)
	}
	d.invalid(m.Subscribe("old-run", stamp(3), "request"))
}

func TestCreatedTimeIsStrictAndCheckedBeforeCloseLock(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Call(Event{ID: "stale", Kind: "request", Stamp: stamp(9)}))
	d.ok(m.Subscribe("sub", stamp(10), "request"))
	d.ok(m.Snapshot("stale"))
	d.ok(m.Call(Event{ID: "equal", Kind: "request", Stamp: stamp(10)}))
	d.ok(m.Snapshot("equal"))
	d.ok(m.Enter("equal"))
	d.ok(m.Receive("equal"))
	d.ok(m.Release("equal"))
	d.ok(m.Return("equal"))
	d.ok(m.Remove("sub"))
	d.ok(m.SignalClose("sub"))
	d.ok(m.BeginJoin("sub"))
	e := d.ok(m.Enter("stale"))
	if e[0].Kind != "stale_dropped" {
		t.Fatal("a stale event waited for the close writer", e)
	}
	d.ok(m.Return("stale"))
	d.ok(m.FinishClose("sub"))
}

func TestCloseJoinsReadersAndRetainsBothReadySelectChoices(t *testing.T) {
	for _, receive := range []bool{false, true} {
		t.Run(map[bool]string{false: "drop", true: "receive"}[receive], func(t *testing.T) {
			d, m := driver{t}, New()
			d.ok(m.Subscribe("sub", stamp(0), "message"))
			for _, id := range []string{"active", "later"} {
				d.ok(m.Call(Event{ID: id, Kind: "message", Stamp: stamp(1)}))
				d.ok(m.Snapshot(id))
			}
			d.ok(m.Enter("active"))
			d.ok(m.Remove("sub"))
			d.ok(m.SignalClose("sub"))
			d.ok(m.BeginJoin("sub"))
			d.blocked(m.Enter("later"))
			d.blocked(m.FinishClose("sub"))
			if receive {
				d.ok(m.Receive("active"))
			} else {
				d.ok(m.Drop("active"))
			}
			// Completion of select alone does not release the delivery lock.
			d.blocked(m.FinishClose("sub"))
			d.ok(m.Release("active"))
			d.ok(m.FinishClose("sub"))
			d.ok(m.Return("active"))
			d.ok(m.Enter("later"))
			d.blocked(m.Receive("later"))
			d.ok(m.Drop("later"))
			d.ok(m.Release("later"))
			d.ok(m.Return("later"))
		})
	}
}

func TestCloseSignalPrecedesWriterPreferenceAndRemovalPrecedesSignal(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("sub", stamp(0), "request"))
	for _, id := range []string{"removed", "signaled"} {
		d.ok(m.Call(Event{ID: id, Kind: "request", Stamp: stamp(1)}))
		d.ok(m.Snapshot(id))
	}
	d.ok(m.Remove("sub"))
	d.ok(m.Enter("removed"))
	d.blocked(m.Drop("removed"))
	d.ok(m.Receive("removed"))
	d.ok(m.Release("removed"))
	d.ok(m.Return("removed"))
	d.ok(m.SignalClose("sub"))
	// Signal alone has not started waiting for the write lock.
	d.ok(m.Enter("signaled"))
	d.ok(m.Receive("signaled"))
	d.ok(m.BeginJoin("sub"))
	d.blocked(m.FinishClose("sub"))
	d.ok(m.Release("signaled"))
	d.ok(m.FinishClose("sub"))
	d.ok(m.Return("signaled"))
}

func TestStopHoldsMuxLockJoinsActiveDeliveryAndRejectsFutureSnapshot(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("sub", stamp(0), "request"))
	for _, id := range []string{"accepted", "waiting"} {
		d.ok(m.Call(Event{ID: id, Kind: "request", Stamp: stamp(1)}))
	}
	d.ok(m.Snapshot("accepted"))
	d.ok(m.Enter("accepted"))
	d.ok(m.BeginStop([]string{"request"}))
	d.blocked(m.Snapshot("waiting"))
	d.blocked(m.Subscribe("blocked-sub", stamp(1), "request"))
	d.blocked(m.Remove("sub"))
	d.blocked(m.AdvanceStop())
	d.ok(m.SignalClose("sub"))
	d.ok(m.BeginJoin("sub"))
	d.blocked(m.FinishClose("sub"))
	d.ok(m.Drop("accepted"))
	d.ok(m.Release("accepted"))
	d.ok(m.FinishClose("sub"))
	d.ok(m.AdvanceStop())
	d.ok(m.FinishStop())
	d.ok(m.Return("accepted"))
	d.ok(m.Snapshot("waiting"))
	d.ok(m.Return("waiting"))
	a, _ := m.Post("accepted")
	w, _ := m.Post("waiting")
	if a.Rejected || !w.Rejected || !m.Stopped() || m.Stopping() {
		t.Fatal(a, w)
	}
	d.ok(m.Subscribe("after-stop", stamp(2), "request"))
	s, _ := m.Subscription("after-stop")
	if s.Phase != Closed || s.Attached {
		t.Fatal(s)
	}
}

func TestStopPreservesNestedTypeTraversalAndRepeatedSubscriberVisits(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("shared", stamp(0), "request", "message"))
	d.ok(m.Subscribe("message-only", stamp(0), "message"))
	d.invalid(m.BeginStop([]string{"message"}))
	d.invalid(m.BeginStop([]string{"message", "message"}))
	d.ok(m.BeginStop([]string{"message", "request"}))
	for _, want := range []string{"shared", "message-only", "shared"} {
		if m.StopCurrent() != want {
			t.Fatal("invalid nested traversal", m.StopCurrent(), want)
		}
		s, _ := m.Subscription(want)
		if s.Phase != Closed {
			d.ok(m.SignalClose(want))
			d.ok(m.BeginJoin(want))
			d.ok(m.FinishClose(want))
		}
		d.ok(m.AdvanceStop())
	}
	d.ok(m.FinishStop())
	// Repeated stop is valid, including an empty subscriber map.
	d.ok(m.BeginStop(nil))
	d.ok(m.FinishStop())
}

func TestStopDoesNotJoinAnAlreadyDetachedSubscription(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("removed", stamp(0), "message"))
	d.ok(m.Call(Event{ID: "old", Kind: "message", Stamp: stamp(1)}))
	d.ok(m.Snapshot("old"))
	d.ok(m.Remove("removed"))
	d.ok(m.BeginStop(nil))
	d.ok(m.FinishStop())
	// The old snapshot remains deliverable after the mux stopped: the
	// concurrent unsubscribe has not signaled its detached instance yet.
	d.ok(m.Enter("old"))
	d.ok(m.Receive("old"))
	d.ok(m.Release("old"))
	d.ok(m.Return("old"))
	d.ok(m.SignalClose("removed"))
	d.ok(m.BeginJoin("removed"))
	d.ok(m.FinishClose("removed"))
}

func TestInspectorsCannotMutateStateAndInvalidRegistrationIsAtomic(t *testing.T) {
	d, m := driver{t}, New()
	d.invalid(m.Subscribe("sub", stamp(0), "message", "message"))
	d.ok(m.Subscribe("sub", stamp(0), "request", "message"))
	d.ok(m.Call(Event{ID: "post", Kind: "message", Stamp: stamp(1)}))
	d.ok(m.Snapshot("post"))
	p, _ := m.Post("post")
	p.Subscriptions[0] = "changed"
	s, _ := m.Subscription("sub")
	s.Kinds[0] = "changed"
	p, _ = m.Post("post")
	s, _ = m.Subscription("sub")
	if p.Subscriptions[0] != "sub" || s.Kinds[0] != "request" {
		t.Fatal("inspection mutated live state")
	}
	d.invalid(m.Call(Event{ID: "post", Kind: "request", Stamp: stamp(2)}))
	d.invalid(m.Receive("post"))
	d.invalid(m.Release("post"))
	d.invalid(m.Return("post"))
	d.invalid(m.SignalClose("sub"))
	d.invalid(m.FinishClose("sub"))
	d.invalid(m.Enter("missing"))
	if _, exists := m.Post("missing"); exists {
		t.Fatal("invalid transition created a post")
	}
}

func TestEmptyRecipientPostReturnsWithoutInventingDelivery(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Call(Event{ID: "empty", Kind: "message", Stamp: stamp(1)}))
	d.ok(m.Snapshot("empty"))
	d.invalid(m.Enter("empty"))
	e := d.ok(m.Return("empty"))
	if e[0].Rejected {
		t.Fatal("no recipients is not a stopped mux")
	}
}
