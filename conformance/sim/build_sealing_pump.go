package sim

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/taskqueue"
)

// pump chooses one runnable application actor. Callbacks use the shared clock;
// ready actor alternatives use the scenario seed and a stable enumeration.
func (b *sealingBuilder) pump() bool {
	if b.closed || !b.started {
		return false
	}
	actions := []func(){}
	if b.stopRequested && !b.seals.CommitBlocked() {
		actions = append(actions, func() { b.stopRequested = false; b.a.n.stop() })
	}
	if b.seals.CommitBlocked() && !b.seals.CommitReady() {
		actions = append(actions, func() { b.sealEffects(b.seals.AcceptCommit()) })
	}
	if b.importing && b.importReturned && b.importHeadPending == 0 {
		actions = append(actions, func() { b.importing = false; b.importReturned = false; b.record("", "import", "returned", nil) })
	}
	if !b.importing && !b.resultDone {
		if b.seals.ResultCount() > 0 {
			actions = append(actions, b.receiveResult)
		}
		if b.closing {
			actions = append(actions, func() { b.resultDone = true; b.record("", "import", "consumer_exited", nil) })
		}
	}
	if len(b.headOffers) > 0 && len(b.heads) < sealingHeadCapacity && !b.assemblerDone {
		actions = append(actions, b.headAccepted)
	}
	if !b.producerDone && b.work.ProducerReady() {
		if b.closing {
			actions = append(actions, func() { b.workEffects(b.work.ChooseProducerExit()); b.producerDone = true })
		}
		if len(b.heads) > 0 {
			actions = append(actions, b.handleHead)
		}
		if len(b.ready) > 0 {
			actions = append(actions, func() {
				choice := 0
				if len(b.ready) > 1 {
					choice = b.a.n.s.rng.IntN(len(b.ready))
				}
				id := b.ready[choice]
				b.ready = append(b.ready[:choice], b.ready[choice+1:]...)
				reason := taskqueue.Resubmit
				// Ready callbacks carry the low 64-bit round value.
				if b.jobs[id].req.Round.RefLow64() == 0 { //wbft:low64 HH-70 ready callback round-zero branch
					reason = taskqueue.NewHead
				}
				b.workEffects(b.work.Trigger(id, reason))
			})
		}
	}
	if !b.producerDone && b.work.OfferedID() != "" && b.closing {
		actions = append(actions, func() { b.workEffects(b.work.AbandonOffer()) })
	}
	if !b.assemblerDone && b.work.ActiveID() == "" {
		if b.closing {
			actions = append(actions, func() { b.workEffects(b.work.ChooseAssemblerExit()); b.assemblerDone = true; b.unsubscribeHeads() })
		}
		if id := b.work.OfferedID(); id != "" {
			actions = append(actions, func() { b.beginWork(id) })
		}
	}
	if id := b.work.ActiveID(); id != "" {
		job := b.jobs[id]
		switch b.work.Phase() {
		case taskqueue.BuildingWork:
			if job.buildReturned {
				actions = append(actions, func() {
					if job.buildOutcome != "" {
						b.workEffects(b.work.Skip(id, job.buildOutcome))
						return
					}
					b.workEffects(b.work.OfferTask(id))
					b.check(b.tasks.Offer(taskqueue.Request{ID: id, Hash: [32]byte(codec.BlockHash(job.block.Header))}))
				})
			}
		case taskqueue.OfferingTask:
			if b.closing && b.tasks.OfferedID() == id {
				actions = append(actions, func() { b.taskEffects(b.tasks.Abandon(id)); b.workEffects(b.work.AbandonTask(id)) })
			}
		case taskqueue.AfterTask:
			actions = append(actions, func() { b.workEffects(b.work.Finish(id)) })
		}
	}
	if !b.tasks.Exited() {
		if id := b.tasks.CallingID(); id != "" {
			if b.jobs[id].callReturned {
				actions = append(actions, func() { b.taskEffects(b.tasks.Return(id, false)) })
			}
		} else {
			if b.closing {
				actions = append(actions, func() { b.taskEffects(b.tasks.ChooseExit()) })
			}
			if id := b.tasks.OfferedID(); id != "" {
				actions = append(actions, func() {
					b.taskEffects(b.tasks.Receive(false))
					b.schedule(0, func() { b.workEffects(b.work.TaskTransferred(id)) })
				})
			}
		}
	}
	for _, id := range b.order {
		job := b.jobs[id]
		switch b.seals.Phase(id) {
		case taskqueue.WaitingMutex:
			if b.seals.Owner() == "" {
				actions = append(actions, func() { b.sealEffects(b.seals.Acquire(id)) })
			}
		case taskqueue.WaitingChoice:
			if b.seals.CommitReady() || b.seals.StopReady(id) {
				actions = append(actions, func() {
					stop := b.seals.StopReady(id)
					if stop && b.seals.CommitReady() {
						stop = b.a.n.s.rng.IntN(2) == 0
					}
					if stop {
						b.sealEffects(b.seals.ChooseStop(id))
					} else {
						b.sealEffects(b.seals.ChooseCommit(id))
					}
				})
			}
		case taskqueue.WaitingResult:
			if b.seals.ResultCount() < b.a.n.spec.Sealing.ResultCapacity {
				actions = append(actions, func() { b.sealEffects(b.seals.SendResult(id)) })
			}
		case taskqueue.WaitingRelease:
			actions = append(actions, func() { b.sealEffects(b.seals.Release(id)) })
		}
		switch b.seals.PostPhase(id) {
		case taskqueue.PostReady:
			if job.postReady {
				actions = append(actions, func() {
					job.postRunner = b.a.n.r
					job.postSubscriber = b.a.n.alive && job.postRunner != nil && job.postRunner.Running()
					b.sealEffects(b.seals.BeginPost(id))
				})
			}
		case taskqueue.PostEntered:
			if !job.postSubscriber || job.postRunner == nil || !job.postRunner.Running() {
				actions = append(actions, func() { b.sealEffects(b.seals.ReturnPost(id, false)) })
			} else if !b.seals.CommitBlocked() {
				actions = append(actions, func() { job.postRunner.Submit(job.block); b.sealEffects(b.seals.DeliverPost(id)) })
			}
		case taskqueue.PostDelivered:
			actions = append(actions, func() { b.sealEffects(b.seals.ReturnPost(id, true)) })
		}
	}
	if b.closing && b.producerDone && b.assemblerDone && b.resultDone && b.tasks.Exited() {
		b.finishClose()
		return true
	}
	if len(actions) == 0 {
		return false
	}
	choice := 0
	if len(actions) > 1 {
		choice = b.a.n.s.rng.IntN(len(actions))
	}
	actions[choice]()
	return true
}
