package taskqueue

import (
	"slices"
	"testing"
)

func workEffects(t *testing.T, got []WorkEffect, err error, want ...WorkEffect) {
	t.Helper()
	if err != nil || !slices.Equal(got, want) {
		t.Fatal(got, err, "want", want)
	}
}
func trigger(t *testing.T, q *WorkQueue, id string, reason Interrupt, want ...WorkEffect) {
	t.Helper()
	got, err := q.Trigger(id, reason)
	workEffects(t, got, err, want...)
}
func acceptWork(t *testing.T, q *WorkQueue, id string) {
	t.Helper()
	got, err := q.Accept()
	workEffects(t, got, err, WorkEffect{ID: id, Kind: WorkAccepted})
}
func resumeWork(t *testing.T, q *WorkQueue) {
	t.Helper()
	if err := q.ResumeProducer(); err != nil {
		t.Fatal(err)
	}
}
func offerWorkTask(t *testing.T, q *WorkQueue, id string) {
	t.Helper()
	got, err := q.OfferTask(id)
	workEffects(t, got, err, WorkEffect{ID: id, Kind: WorkTaskOffered})
}
func transferWorkTask(t *testing.T, q *WorkQueue, id string) {
	t.Helper()
	got, err := q.TaskTransferred(id)
	workEffects(t, got, err, WorkEffect{ID: id, Kind: WorkTaskTransferred})
	got, err = q.Finish(id)
	workEffects(t, got, err, WorkEffect{ID: id, Kind: WorkFinished, Outcome: Returned})
}
func TestAssemblyAndSealingCallsHaveIndependentOwnership(t *testing.T) {
	w, s := NewWorkQueue(), New()
	trigger(t, w, "one", NewHead, WorkEffect{ID: "one", Kind: WorkOffered})
	acceptWork(t, w, "one")
	if _, err := w.Trigger("two", Resubmit); err == nil {
		t.Fatal("sender resumed implicitly")
	}
	resumeWork(t, w)
	trigger(t, w, "two", Resubmit, WorkEffect{ID: "one", Kind: WorkInterrupted, Interrupt: Resubmit}, WorkEffect{ID: "two", Kind: WorkOffered})
	if signal, ok := w.InterruptOf("one"); !ok || signal != Resubmit {
		t.Fatal("interrupt deferred until new handoff")
	}
	if _, err := w.Accept(); err == nil {
		t.Fatal("parallel assembly")
	}
	offerWorkTask(t, w, "one")
	offer(t, s, "one", 1)
	if _, err := w.Finish("one"); err == nil {
		t.Fatal("work finished before task transfer")
	}
	receive(t, s, false, Effect{ID: "one", Kind: Received}, Effect{ID: "one", Kind: CallSeal})
	transferWorkTask(t, w, "one")
	acceptWork(t, w, "two")
	resumeWork(t, w)
	offerWorkTask(t, w, "two")
	offer(t, s, "two", 2)
	if _, err := s.Receive(false); err == nil {
		t.Fatal("received another task while Seal caller blocked")
	}
	returned(t, s, "one", false)
	receive(t, s, false, Effect{ID: "two", Kind: Received}, Effect{ID: "one", Kind: CancelSeal}, Effect{ID: "two", Kind: CallSeal})
	transferWorkTask(t, w, "two")
	returned(t, s, "two", false)
	if w.ActiveID() != "" || w.Phase() != WorkIdle || s.StopOwner() != "two" || s.PendingID(hash(1)) != "one" {
		t.Fatal("work return fabricated sealing completion")
	}
}
func TestExitDoesNotEraseInterruptOrCompleteBlockedTask(t *testing.T) {
	w, s := NewWorkQueue(), New()
	trigger(t, w, "one", NewHead, WorkEffect{ID: "one", Kind: WorkOffered})
	acceptWork(t, w, "one")
	resumeWork(t, w)
	trigger(t, w, "two", Resubmit, WorkEffect{ID: "one", Kind: WorkInterrupted, Interrupt: Resubmit}, WorkEffect{ID: "two", Kind: WorkOffered})
	w.RequestExit()
	s.RequestExit()
	if _, err := w.ChooseProducerExit(); err == nil {
		t.Fatal("producer exited without choosing its blocked send")
	}
	got, err := w.AbandonOffer()
	workEffects(t, got, err, WorkEffect{ID: "two", Kind: WorkAbandoned})
	got, err = w.ChooseProducerExit()
	workEffects(t, got, err, WorkEffect{Kind: WorkProducerExited})
	if signal, _ := w.InterruptOf("one"); signal != Resubmit {
		t.Fatal("abandoned new work erased earlier interrupt")
	}
	if _, err = w.ChooseAssemblerExit(); err == nil {
		t.Fatal("exit completed active assembly")
	}
	offerWorkTask(t, w, "one")
	offer(t, s, "one", 1)
	effectsGot, e := s.ChooseExit()
	effects(t, effectsGot, e, Effect{Kind: Exited})
	effectsGot, e = s.Abandon("one")
	effects(t, effectsGot, e, Effect{ID: "one", Kind: Abandoned})
	got, err = w.AbandonTask("one")
	workEffects(t, got, err, WorkEffect{ID: "one", Kind: WorkTaskAbandoned})
	got, err = w.Finish("one")
	workEffects(t, got, err, WorkEffect{ID: "one", Kind: WorkFinished, Outcome: Returned})
	got, err = w.ChooseAssemblerExit()
	workEffects(t, got, err, WorkEffect{Kind: WorkAssemblerExited})
}
func TestAssemblySkipIsExplicitAndRendezvousCanLoseToExit(t *testing.T) {
	for _, outcome := range []WorkOutcome{Syncing, MissingCoinbase, PrepareFailed, FinalizeFailed, NotRunning, TerminalDifficulty} {
		t.Run(string(outcome), func(t *testing.T) {
			q := NewWorkQueue()
			trigger(t, q, "one", NewHead, WorkEffect{ID: "one", Kind: WorkOffered})
			acceptWork(t, q, "one")
			resumeWork(t, q)
			if _, err := q.Skip("wrong", outcome); err == nil {
				t.Fatal("stale skip")
			}
			if _, err := q.Skip("one", Returned); err == nil {
				t.Fatal("success return invented a task handoff")
			}
			got, err := q.Skip("one", outcome)
			workEffects(t, got, err, WorkEffect{ID: "one", Kind: WorkFinished, Outcome: outcome})
			trigger(t, q, "two", NewHead, WorkEffect{ID: "one", Kind: WorkInterrupted, Interrupt: NewHead}, WorkEffect{ID: "two", Kind: WorkOffered})
			q.RequestExit()
			got, err = q.ChooseAssemblerExit()
			workEffects(t, got, err, WorkEffect{Kind: WorkAssemblerExited})
			if _, err = q.Accept(); err == nil {
				t.Fatal("accepted after assembler exit")
			}
			got, err = q.AbandonOffer()
			workEffects(t, got, err, WorkEffect{ID: "two", Kind: WorkAbandoned})
			got, err = q.ChooseProducerExit()
			workEffects(t, got, err, WorkEffect{Kind: WorkProducerExited})
			if _, err = q.Trigger("three", NewHead); err == nil {
				t.Fatal("trigger after producer exit")
			}
		})
	}
}

func TestNewHeadSkipRequiresDeliveredInterrupt(t *testing.T) {
	q := NewWorkQueue()
	trigger(t, q, "one", NewHead, WorkEffect{ID: "one", Kind: WorkOffered})
	acceptWork(t, q, "one")
	resumeWork(t, q)
	if _, err := q.Skip("one", InterruptedNewHead); err == nil || q.ActiveID() != "one" {
		t.Fatal("NewHead skip invented interruption")
	}
	trigger(t, q, "two", Resubmit, WorkEffect{ID: "one", Kind: WorkInterrupted, Interrupt: Resubmit}, WorkEffect{ID: "two", Kind: WorkOffered})
	if _, err := q.Skip("one", InterruptedNewHead); err == nil {
		t.Fatal("resubmit converted to NewHead discard")
	}
	got, err := q.OfferTask("one")
	workEffects(t, got, err, WorkEffect{ID: "one", Kind: WorkTaskOffered})
	transferWorkTask(t, q, "one")
	acceptWork(t, q, "two")
	resumeWork(t, q)
	trigger(t, q, "three", NewHead, WorkEffect{ID: "two", Kind: WorkInterrupted, Interrupt: NewHead}, WorkEffect{ID: "three", Kind: WorkOffered})
	got, err = q.Skip("two", InterruptedNewHead)
	workEffects(t, got, err, WorkEffect{ID: "two", Kind: WorkFinished, Outcome: InterruptedNewHead})
}
