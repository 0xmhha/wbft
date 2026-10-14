package buildqueue

import (
	"github.com/0xmhha/wbft/app"
	"testing"
	"time"
)

func effects(t *testing.T, got []Effect, e error, kind Kind, id string, status app.BuildStatus) {
	t.Helper()
	if e != nil || len(got) != 1 || got[0].Kind != kind || got[0].ID != id || got[0].Status != status {
		t.Fatal(got, e)
	}
}
func offer(t *testing.T, q *Queue, id string, wait time.Duration) {
	t.Helper()
	got, e := q.Offer(Request{id, wait})
	if e != nil || len(got) != 0 {
		t.Fatal(got, e)
	}
}
func TestQueuedAndWaitingReplacementKeepExactNextRequest(t *testing.T) {
	q := New()
	q.Stop()
	offer(t, q, "old", time.Hour)
	got, e := q.Offer(Request{"next", time.Second})
	effects(t, got, e, Finished, "old", app.BuildReplaced)
	if e = q.Start(); e != nil {
		t.Fatal(e)
	}
	got, e = q.Select(true)
	effects(t, got, e, ArmWait, "next", "")
	offer(t, q, "newer", 2*time.Second)
	got, e = q.Choose("next", NewerRequest)
	effects(t, got, e, Finished, "next", app.BuildReplaced)
	if _, e = q.Choose("next", TimerReady); e == nil {
		t.Fatal("stale timer advanced replacement")
	}
	got, e = q.Select(true)
	effects(t, got, e, ArmWait, "newer", "")
	if got[0].Wait != 2*time.Second {
		t.Fatal("wait was charged at offer instead of selection")
	}
}
func TestAssemblyRetainsWorkerWhilePendingLatestChanges(t *testing.T) {
	q := New()
	offer(t, q, "active", 0)
	got, e := q.Select(true)
	effects(t, got, e, CheckHead, "active", "")
	got, e = q.Head("active", true)
	effects(t, got, e, AssemblyStarted, "active", "")
	offer(t, q, "pending", time.Second)
	got, e = q.Offer(Request{"latest", time.Second})
	effects(t, got, e, Finished, "pending", app.BuildReplaced)
	if _, e = q.Select(true); e == nil {
		t.Fatal("parallel assembly entered")
	}
	got, e = q.Done("active")
	effects(t, got, e, CancelAssembly, "active", "")
	if q.ActiveID() != "active" {
		t.Fatal("Done freed worker before executor return")
	}
	if got = q.Stop(); len(got) != 0 || q.ActiveID() != "active" {
		t.Fatal("Stop cancelled assembly", got)
	}
	if e = q.Start(); e == nil {
		t.Fatal("restart raced in-flight executor")
	}
	got, e = q.Complete("active", app.BuildFailed)
	effects(t, got, e, Finished, "active", app.BuildFailed)
	if e = q.Start(); e != nil {
		t.Fatal(e)
	}
	got, e = q.Select(true)
	effects(t, got, e, ArmWait, "latest", "")
}
func TestEarlyReturnsNeverInventAssembly(t *testing.T) {
	for _, status := range []app.BuildStatus{app.BuildUnavailable, app.BuildHeightLeft, app.BuildStopped, app.BuildHeadChanged} {
		q := New()
		offer(t, q, "r", time.Hour)
		got, e := q.Select(status != app.BuildUnavailable)
		switch status {
		case app.BuildUnavailable:
			effects(t, got, e, Finished, "r", status)
		case app.BuildHeightLeft:
			got, e = q.Done("r")
			effects(t, got, e, Finished, "r", status)
		case app.BuildStopped:
			got = q.Stop()
			effects(t, got, nil, Finished, "r", status)
		case app.BuildHeadChanged:
			_, e = q.Choose("r", TimerReady)
			if e != nil {
				t.Fatal(e)
			}
			got, e = q.Head("r", false)
			effects(t, got, e, Finished, "r", status)
		}
		if q.Phase() != Idle {
			t.Fatal("early return kept active worker")
		}
	}
}
func TestZeroWaitAndStopDoNotPreemptExecutorReturn(t *testing.T) {
	q := New()
	offer(t, q, "r", 0)
	if _, e := q.Select(true); e != nil {
		t.Fatal(e)
	}
	q.Stop()
	got, e := q.Head("r", true)
	effects(t, got, e, AssemblyStarted, "r", "")
	got, e = q.Complete("r", app.BuildSubmitted)
	effects(t, got, e, Finished, "r", app.BuildSubmitted)
	if _, e = q.Complete("r", app.BuildSubmitted); e == nil {
		t.Fatal("duplicate return accepted")
	}
	if _, e = q.Offer(Request{"r", 0}); e == nil {
		t.Fatal("request identity reused")
	}
}
