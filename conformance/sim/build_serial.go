package sim

import (
	"fmt"
	"time"

	application "github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/buildqueue"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

const BuildQueueSerial = "serial-latest"
const BuildDoneFails = "failed"
const BuildDoneSubmits = "submitted"

type serialJob struct {
	req       consensus.RequestBuild
	done      <-chan struct{}
	parent    types.Hash
	writer    *event.Writer
	clock     *nodeClock
	block     *types.Block
	runner    *runner.Runner
	cancelled bool
}
type serialBuilder struct {
	a                        *app
	q                        *buildqueue.Queue
	jobs                     map[string]*serialJob
	next                     uint64
	waitTimer, assemblyTimer runner.Timer
	waitID                   string
	restart                  bool
}

func newSerialBuilder(a *app) *serialBuilder {
	return &serialBuilder{a: a, q: buildqueue.New(), jobs: map[string]*serialJob{}}
}
func (b *serialBuilder) effects(rows []buildqueue.Effect, e error) {
	if e != nil {
		b.a.n.s.violate("application_queue", b.a.n.v.address, "%v", e)
		return
	}
	for _, row := range rows {
		job := b.jobs[row.ID]
		if job == nil {
			b.a.n.s.violate("application_queue", b.a.n.v.address, "unknown request")
			continue
		}
		switch row.Kind {
		case buildqueue.ArmWait:
			id := row.ID
			b.waitID = id
			b.waitTimer = b.a.n.s.l.after(row.Wait, func() {
				if b.waitID == id {
					b.waitTimer = nil
					b.waitID = ""
				}
				if b.q.ActiveID() == id && b.q.Phase() == buildqueue.Waiting {
					b.effects(b.q.Choose(id, buildqueue.TimerReady))
				}
			})
		case buildqueue.CheckHead:
			head := b.a.chain.head.Header
			b.effects(b.q.Head(row.ID, head != nil && head.Number.AddUint64(1).Cmp(job.req.Height) == 0 && codec.BlockHash(head) == job.parent))
		case buildqueue.AssemblyStarted:
			b.emit(job, row.ID, event.BuildStarted, "")
			job.runner = b.a.n.r
			if job.runner == nil {
				b.effects(b.q.Complete(row.ID, application.BuildFailed))
				continue
			}
			block, err := b.a.build(b.a.chain.head.Header)
			if err != nil {
				b.effects(b.q.Complete(row.ID, application.BuildFailed))
				continue
			}
			job.block = block
			samples := b.a.n.s.sc.App.BuildDelay
			if len(b.a.n.spec.BuildDelay) > 0 {
				samples = b.a.n.spec.BuildDelay
			}
			id := row.ID
			b.assemblyTimer = b.a.n.s.l.after(sample(b.a.n.s.rng, samples), func() {
				b.assemblyTimer = nil
				if b.q.ActiveID() != id {
					return
				}
				b.pollDone()
				status := application.BuildSubmitted
				if job.cancelled && b.a.n.spec.BuildDoneResult == BuildDoneFails {
					status = application.BuildFailed
				} else {
					job.runner.Submit(job.block)
				}
				b.effects(b.q.Complete(id, status))
				if b.restart {
					b.restart = false
					b.a.n.start()
				}
			})
		case buildqueue.CancelAssembly:
			job.cancelled = true
		case buildqueue.Finished:
			if b.waitTimer != nil && b.waitID == row.ID {
				b.waitTimer.Stop()
				b.waitTimer = nil
				b.waitID = ""
			}
			b.emit(job, row.ID, event.BuildFinished, row.Status)
			delete(b.jobs, row.ID)
		}
	}
}
func (b *serialBuilder) emit(job *serialJob, id string, kind event.Kind, status application.BuildStatus) {
	fields := map[string]any{"build_id": id, "number": job.req.Height.String()}
	if kind == event.BuildFinished {
		fields["status"] = string(status)
		if status == application.BuildSubmitted && job.block != nil {
			fields["hash"] = codec.BlockHash(job.block.Header).Hex()
		}
	}
	if job.writer != nil {
		_ = job.writer.Write(event.Record{Kind: kind, View: event.ViewOf(types.View{Sequence: job.req.Height, Round: job.req.Round}), Fields: fields}, event.Stamp{Wall: job.clock.Now(), Mono: job.clock.Mono()})
	}
}
func (b *serialBuilder) offer(req consensus.RequestBuild, wait time.Duration, done <-chan struct{}) {
	b.next++
	id := fmt.Sprintf("build-%d", b.next)
	job := &serialJob{req: req, done: done, writer: b.a.n.ev, clock: b.a.n.clock}
	if head := b.a.chain.head.Header; head.Number.AddUint64(1).Cmp(req.Height) == 0 {
		job.parent = codec.BlockHash(head)
	}
	b.jobs[id] = job
	if job.writer != nil {
		_ = job.writer.Write(event.Record{Kind: event.BuildHandover, View: event.ViewOf(types.View{Sequence: req.Height, Round: req.Round}), Fields: map[string]any{"build_id": id, "number": req.Height.String(), "wait_ns": fmt.Sprint(int64(wait)), "parent": job.parent.Hex()}}, event.Stamp{Wall: job.clock.Now(), Mono: job.clock.Mono()})
	}
	b.effects(b.q.Offer(buildqueue.Request{ID: id, Wait: wait}))
}
func (b *serialBuilder) pollDone() bool {
	id := b.q.ActiveID()
	job := b.jobs[id]
	if job == nil || job.cancelled {
		return false
	}
	select {
	case <-job.done:
		if b.q.Phase() == buildqueue.Waiting || b.q.Phase() == buildqueue.Assembling {
			b.effects(b.q.Done(id))
			return true
		}
	default:
	}
	return false
}
func (b *serialBuilder) pump() bool {
	if b.pollDone() {
		return true
	}
	if b.q.Stopped() {
		return false
	}
	if b.q.Phase() == buildqueue.Waiting && b.q.Pending() {
		b.effects(b.q.Choose(b.q.ActiveID(), buildqueue.NewerRequest))
		return true
	}
	if b.q.Phase() == buildqueue.Idle && b.q.Pending() {
		b.effects(b.q.Select(b.a.n.r != nil && b.a.n.alive))
		return true
	}
	return false
}
func (b *serialBuilder) stop() { b.effects(b.q.Stop(), nil); b.pollDone() }
func (b *serialBuilder) start() {
	if e := b.q.Start(); e != nil {
		b.a.n.s.violate("application_queue", b.a.n.v.address, "%v", e)
	}
}
func (b *serialBuilder) deferStart() bool {
	if b.q.Stopped() && b.q.ActiveID() != "" {
		b.restart = true
		return true
	}
	return false
}
func (b *serialBuilder) crash() {
	if b.waitTimer != nil {
		b.waitTimer.Stop()
	}
	if b.assemblyTimer != nil {
		b.assemblyTimer.Stop()
	}
	b.q = buildqueue.New()
	b.jobs = map[string]*serialJob{}
	b.restart = false
}
