package taskqueue

// Interrupt is the signal delivered to the previously generated work, even
// when the new work producer is still blocked on its unbuffered handoff.
type Interrupt uint8

const (
	NoInterrupt Interrupt = iota
	NewHead
	Resubmit
)

type WorkPhase uint8

const (
	WorkIdle WorkPhase = iota
	BuildingWork
	OfferingTask
	AfterTask
)

type WorkKind uint8

const (
	WorkOffered WorkKind = iota
	WorkInterrupted
	WorkAccepted
	WorkTaskOffered
	WorkTaskTransferred
	WorkTaskAbandoned
	WorkFinished
	WorkAbandoned
	WorkProducerExited
	WorkAssemblerExited
)

type WorkOutcome string

const (
	Returned           WorkOutcome = "returned"
	Syncing            WorkOutcome = "syncing"
	MissingCoinbase    WorkOutcome = "missing_coinbase"
	PrepareFailed      WorkOutcome = "prepare_failed"
	InterruptedNewHead WorkOutcome = "interrupted_new_head"
	FinalizeFailed     WorkOutcome = "finalize_failed"
	NotRunning         WorkOutcome = "not_running"
	TerminalDifficulty WorkOutcome = "terminal_difficulty"
)

const AssemblyFailed WorkOutcome = "assembly_failed"

type WorkEffect struct {
	ID        string
	Kind      WorkKind
	Interrupt Interrupt
	Outcome   WorkOutcome
}
type work struct {
	id        string
	interrupt Interrupt
}

// WorkQueue keeps the work producer, serial assembly and task sender separate.
// Ready callbacks, transaction interrupt checks, and sealing results are inputs
// owned by other actors. Making exit ready never invents their completion.
type WorkQueue struct {
	offered, active, last                      *work
	phase                                      WorkPhase
	producerBusy, awaitResume                  bool
	exitReady, producerExited, assemblerExited bool
	history                                    map[string]*work
}

func NewWorkQueue() *WorkQueue        { return &WorkQueue{history: map[string]*work{}} }
func (q *WorkQueue) Phase() WorkPhase { return q.phase }
func (q *WorkQueue) ActiveID() string {
	if q.active == nil {
		return ""
	}
	return q.active.id
}
func (q *WorkQueue) OfferedID() string {
	if q.offered == nil {
		return ""
	}
	return q.offered.id
}
func (q *WorkQueue) InterruptOf(id string) (Interrupt, bool) {
	w, ok := q.history[id]
	if !ok {
		return NoInterrupt, false
	}
	return w.interrupt, true
}

// Trigger is chosen by the work loop after receiving a ready/head event. It
// signals the old request before the next request can be accepted by assembly.
func (q *WorkQueue) Trigger(id string, reason Interrupt) ([]WorkEffect, error) {
	if id == "" || q.history[id] != nil || q.producerExited || q.producerBusy || reason != NewHead && reason != Resubmit {
		return nil, ErrTransition
	}
	out := []WorkEffect{}
	if q.last != nil {
		q.last.interrupt = reason
		out = append(out, WorkEffect{ID: q.last.id, Kind: WorkInterrupted, Interrupt: reason})
	}
	w := &work{id: id}
	q.history[id] = w
	q.last = w
	q.offered = w
	q.producerBusy = true
	return append(out, WorkEffect{ID: id, Kind: WorkOffered}), nil
}
func (q *WorkQueue) Accept() ([]WorkEffect, error) {
	if q.assemblerExited || q.active != nil || q.offered == nil {
		return nil, ErrTransition
	}
	q.active = q.offered
	q.offered = nil
	q.awaitResume = true
	q.phase = BuildingWork
	return []WorkEffect{{ID: q.active.id, Kind: WorkAccepted}}, nil
}

// ResumeProducer records the sender running after its rendezvous. Assembly may
// already be active; accepting work does not implicitly schedule the sender.
func (q *WorkQueue) ResumeProducer() error {
	if !q.awaitResume || !q.producerBusy {
		return ErrTransition
	}
	q.awaitResume = false
	q.producerBusy = false
	return nil
}
func (q *WorkQueue) OfferTask(id string) ([]WorkEffect, error) {
	if q.active == nil || q.active.id != id || q.phase != BuildingWork {
		return nil, ErrTransition
	}
	q.phase = OfferingTask
	return []WorkEffect{{ID: id, Kind: WorkTaskOffered}}, nil
}
func (q *WorkQueue) TaskTransferred(id string) ([]WorkEffect, error) {
	if q.active == nil || q.active.id != id || q.phase != OfferingTask {
		return nil, ErrTransition
	}
	q.phase = AfterTask
	return []WorkEffect{{ID: id, Kind: WorkTaskTransferred}}, nil
}
func (q *WorkQueue) AbandonTask(id string) ([]WorkEffect, error) {
	if !q.exitReady || q.active == nil || q.active.id != id || q.phase != OfferingTask {
		return nil, ErrTransition
	}
	q.phase = AfterTask
	return []WorkEffect{{ID: id, Kind: WorkTaskAbandoned}}, nil
}
func (q *WorkQueue) Finish(id string) ([]WorkEffect, error) {
	if q.active == nil || q.active.id != id || q.phase != AfterTask {
		return nil, ErrTransition
	}
	return q.finish(Returned), nil
}
func (q *WorkQueue) Skip(id string, outcome WorkOutcome) ([]WorkEffect, error) {
	if q.active == nil || q.active.id != id || q.phase != BuildingWork {
		return nil, ErrTransition
	}
	if outcome == InterruptedNewHead && q.active.interrupt != NewHead {
		return nil, ErrTransition
	}
	switch outcome {
	case Syncing, MissingCoinbase, PrepareFailed, InterruptedNewHead, FinalizeFailed, AssemblyFailed, NotRunning, TerminalDifficulty:
	default:
		return nil, ErrTransition
	}
	return q.finish(outcome), nil
}
func (q *WorkQueue) finish(outcome WorkOutcome) []WorkEffect {
	out := []WorkEffect{{ID: q.active.id, Kind: WorkFinished, Outcome: outcome}}
	q.active = nil
	q.phase = WorkIdle
	return out
}
func (q *WorkQueue) RequestExit() { q.exitReady = true }
func (q *WorkQueue) AbandonOffer() ([]WorkEffect, error) {
	if !q.exitReady || q.offered == nil {
		return nil, ErrTransition
	}
	id := q.offered.id
	q.offered = nil
	q.producerBusy = false
	return []WorkEffect{{ID: id, Kind: WorkAbandoned}}, nil
}
func (q *WorkQueue) ChooseProducerExit() ([]WorkEffect, error) {
	if !q.exitReady || q.producerExited || q.producerBusy {
		return nil, ErrTransition
	}
	q.producerExited = true
	return []WorkEffect{{Kind: WorkProducerExited}}, nil
}
func (q *WorkQueue) ChooseAssemblerExit() ([]WorkEffect, error) {
	if !q.exitReady || q.assemblerExited || q.active != nil {
		return nil, ErrTransition
	}
	q.assemblerExited = true
	return []WorkEffect{{Kind: WorkAssemblerExited}}, nil
}

func (q *WorkQueue) ProducerReady() bool { return !q.producerBusy && !q.producerExited }
