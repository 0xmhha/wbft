package taskqueue

import (
	"slices"
	"testing"
)

func hash(n byte) [32]byte { var h [32]byte; h[31] = n; return h }
func offer(t *testing.T, q *Queue, id string, n byte) {
	t.Helper()
	if err := q.Offer(Request{ID: id, Hash: hash(n)}); err != nil {
		t.Fatal(err)
	}
}
func effects(t *testing.T, got []Effect, err error, want ...Effect) {
	t.Helper()
	if err != nil || !slices.Equal(got, want) {
		t.Fatal(got, err, "want", want)
	}
}
func receive(t *testing.T, q *Queue, skip bool, want ...Effect) {
	t.Helper()
	got, err := q.Receive(skip)
	effects(t, got, err, want...)
}
func returned(t *testing.T, q *Queue, id string, failed bool) {
	t.Helper()
	got, err := q.Return(id, failed)
	effects(t, got, err, Effect{ID: id, Kind: SealReturned, Failed: failed})
}
func TestUnbufferedHandoffAndAsynchronousOwnership(t *testing.T) {
	q := New()
	offer(t, q, "one", 1)
	if q.CallingID() != "" || q.StopOwner() != "" || q.PendingID(hash(1)) != "" {
		t.Fatal("offer completed a rendezvous")
	}
	receive(t, q, false, Effect{ID: "one", Kind: Received}, Effect{ID: "one", Kind: CallSeal})
	offer(t, q, "duplicate", 1)
	if _, err := q.Receive(false); err == nil {
		t.Fatal("received during synchronous Seal call")
	}
	returned(t, q, "one", false)
	if q.StopOwner() != "one" || q.PendingID(hash(1)) != "one" {
		t.Fatal("return fabricated asynchronous completion")
	}
	receive(t, q, false, Effect{ID: "duplicate", Kind: Received}, Effect{ID: "duplicate", Kind: Duplicate})
	if q.StopOwner() != "one" {
		t.Fatal("duplicate replaced cancellation owner")
	}
	offer(t, q, "two", 2)
	receive(t, q, false, Effect{ID: "two", Kind: Received}, Effect{ID: "one", Kind: CancelSeal}, Effect{ID: "two", Kind: CallSeal})
	returned(t, q, "two", true)
	if q.StopOwner() != "two" || q.PendingID(hash(2)) != "" || q.PendingID(hash(1)) != "one" {
		t.Fatal("failed Seal changed previous hash/stop or unrelated pending state")
	}
	offer(t, q, "retry", 2)
	receive(t, q, false, Effect{ID: "retry", Kind: Received}, Effect{ID: "retry", Kind: Duplicate})
}
func TestSkippedAndZeroHashTasksRetainDuplicateSemantics(t *testing.T) {
	q := New()
	offer(t, q, "zero", 0)
	receive(t, q, true, Effect{ID: "zero", Kind: Received}, Effect{ID: "zero", Kind: Duplicate})
	if q.StopOwner() != "" {
		t.Fatal("initial duplicate created a stop channel")
	}
	offer(t, q, "skip", 1)
	receive(t, q, true, Effect{ID: "skip", Kind: Received}, Effect{ID: "skip", Kind: Skipped})
	if q.StopOwner() != "skip" || q.PendingID(hash(1)) != "" {
		t.Fatal("skip does not match task-loop order")
	}
	offer(t, q, "duplicate", 1)
	receive(t, q, false, Effect{ID: "duplicate", Kind: Received}, Effect{ID: "duplicate", Kind: Duplicate})
	offer(t, q, "next", 2)
	receive(t, q, false, Effect{ID: "next", Kind: Received}, Effect{ID: "skip", Kind: CancelSeal}, Effect{ID: "next", Kind: CallSeal})
}
func TestExitReadyDoesNotPreemptSealOrChooseRendezvousOrder(t *testing.T) {
	for _, selection := range []string{"abandon", "receive"} {
		t.Run(selection, func(t *testing.T) {
			q := New()
			offer(t, q, "one", 1)
			receive(t, q, false, Effect{ID: "one", Kind: Received}, Effect{ID: "one", Kind: CallSeal})
			offer(t, q, "two", 2)
			q.RequestExit()
			if _, err := q.ChooseExit(); err == nil {
				t.Fatal("exit preempted Seal")
			}
			returned(t, q, "one", false)
			if selection == "receive" {
				receive(t, q, false, Effect{ID: "two", Kind: Received}, Effect{ID: "one", Kind: CancelSeal}, Effect{ID: "two", Kind: CallSeal})
				returned(t, q, "two", false)
			} else {
				got, err := q.Abandon("two")
				effects(t, got, err, Effect{ID: "two", Kind: Abandoned})
			}
			owner := q.StopOwner()
			got, err := q.ChooseExit()
			effects(t, got, err, Effect{ID: owner, Kind: CancelSeal}, Effect{Kind: Exited})
			if !q.Exited() || q.StopOwner() != "" {
				t.Fatal("exit incomplete")
			}
			// A different loop may reach its send after the receiver has exited.
			if err = q.Offer(Request{ID: "late", Hash: hash(3)}); err != nil {
				t.Fatal(err)
			}
			if _, err = q.Receive(false); err == nil {
				t.Fatal("receiver resumed after exit")
			}
			got, err = q.Abandon("late")
			effects(t, got, err, Effect{ID: "late", Kind: Abandoned})
		})
	}
}
func TestPendingReuseAndInvalidTransitionsPreserveState(t *testing.T) {
	q := New()
	if _, err := q.Receive(false); err == nil {
		t.Fatal("received without producer")
	}
	if _, err := q.Return("one", false); err == nil {
		t.Fatal("returned without call")
	}
	if _, err := q.ChooseExit(); err == nil {
		t.Fatal("exit not ready")
	}
	offer(t, q, "one", 1)
	if err := q.Offer(Request{ID: "two", Hash: hash(2)}); err == nil {
		t.Fatal("overwrote blocked producer")
	}
	if _, err := q.Abandon("one"); err == nil {
		t.Fatal("abandoned without exit")
	}
	receive(t, q, false, Effect{ID: "one", Kind: Received}, Effect{ID: "one", Kind: CallSeal})
	if _, err := q.Return("wrong", false); err == nil || q.CallingID() != "one" {
		t.Fatal("stale return changed owner")
	}
	returned(t, q, "one", false)
	offer(t, q, "two", 2)
	receive(t, q, false, Effect{ID: "two", Kind: Received}, Effect{ID: "one", Kind: CancelSeal}, Effect{ID: "two", Kind: CallSeal})
	returned(t, q, "two", false)
	offer(t, q, "three", 1)
	receive(t, q, false, Effect{ID: "three", Kind: Received}, Effect{ID: "two", Kind: CancelSeal}, Effect{ID: "three", Kind: CallSeal})
	returned(t, q, "three", false)
	if err := q.Forget(hash(1), "one"); err == nil || q.PendingID(hash(1)) != "three" {
		t.Fatal("stale cleanup removed reused hash")
	}
	if err := q.Forget(hash(1), "three"); err != nil || q.PendingID(hash(1)) != "" {
		t.Fatal(err)
	}
	if err := q.Offer(Request{ID: "one", Hash: hash(1)}); err == nil {
		t.Fatal("reused request identity")
	}
}
