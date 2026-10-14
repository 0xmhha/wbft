package sim

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/taskqueue"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

const BuildQueueSealing = "unbuffered-seal"
const SealingSeeded = "seeded"
const sealingStage event.Kind = "SIM_SEALING_STAGE"
const sealingHeadCapacity = 10
const sealingPendingAge = 7

// SealingProfile declares a fake empty-body executor and actor scheduler. It
// never infers physical executor or event-loop behavior from observed timings.
type SealingProfile struct {
	Selection      string
	ResultCapacity int
	CallDelay      []time.Duration
	PostDelay      []time.Duration
}
type sealingJob struct {
	req                                    consensus.RequestBuild
	writer                                 *event.Writer
	clock                                  *nodeClock
	block                                  *types.Block
	buildReturned, callReturned, postReady bool
	buildOutcome                           taskqueue.WorkOutcome
	postRunner                             *runner.Runner
	postSubscriber                         bool
}
type sealingHead struct {
	header *types.Header
	local  bool
}
type sealingBuilder struct {
	a                                       *app
	work                                    *taskqueue.WorkQueue
	tasks                                   *taskqueue.Queue
	seals                                   *taskqueue.Sealer
	jobs                                    map[string]*sealingJob
	order, ready                            []string
	timers                                  []runner.Timer
	blocks                                  map[string]*types.Block
	completions                             map[string]func(error)
	heads, headOffers                       []sealingHead
	next, commitNext                        uint64
	started, closing, closed                bool
	producerDone, assemblerDone, resultDone bool
	stopRequested, restart                  bool
	importing, importReturned               bool
	importHeadPending                       int
	localPublish                            bool
}

func newSealingBuilder(a *app) *sealingBuilder {
	s, err := taskqueue.NewSealer(a.n.spec.Sealing.ResultCapacity)
	if err != nil {
		panic(err)
	}
	return &sealingBuilder{a: a, work: taskqueue.NewWorkQueue(), tasks: taskqueue.New(), seals: s, jobs: map[string]*sealingJob{}, blocks: map[string]*types.Block{}, completions: map[string]func(error){}}
}
func (b *sealingBuilder) schedule(delay time.Duration, f func()) {
	b.timers = append(b.timers, b.a.n.s.l.after(delay, func() {
		if !b.closed {
			f()
		}
	}))
}
func (b *sealingBuilder) record(id, actor, stage string, fields map[string]any) {
	writer, clock := b.a.n.ev, b.a.n.clock
	if job := b.jobs[id]; job != nil {
		writer, clock = job.writer, job.clock
	}
	if writer == nil || clock == nil {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["actor"], fields["stage"] = actor, stage
	if id != "" {
		fields["work_id"] = id
	}
	if job := b.jobs[id]; job != nil {
		fields["request_height"], fields["request_round"] = job.req.Height.String(), job.req.Round.String()
		if job.block != nil {
			fields["number"], fields["hash"] = job.block.Header.Number.String(), codec.BlockHash(job.block.Header).Hex()
		}
	}
	_ = writer.Write(event.Record{Kind: sealingStage, Src: event.AppSrc, Fields: fields}, event.Stamp{Wall: clock.Now(), Mono: clock.Mono()})
}
func (b *sealingBuilder) check(err error) bool {
	if err != nil {
		b.a.n.s.violate("application_queue", b.a.n.v.address, "%v", err)
		return false
	}
	return true
}
func (b *sealingBuilder) workEffects(rows []taskqueue.WorkEffect, err error) {
	if !b.check(err) {
		return
	}
	names := []string{"offered", "interrupted", "accepted", "task_offered", "task_transferred", "task_abandoned", "finished", "abandoned", "producer_exited", "assembler_exited"}
	for _, row := range rows {
		fields := map[string]any{}
		if row.Interrupt != taskqueue.NoInterrupt {
			fields["interrupt"] = []string{"none", "new_head", "resubmit"}[row.Interrupt]
		}
		if row.Outcome != "" {
			fields["outcome"] = string(row.Outcome)
		}
		b.record(row.ID, "work", names[row.Kind], fields)
	}
}
func (b *sealingBuilder) taskEffects(rows []taskqueue.Effect, err error) {
	if !b.check(err) {
		return
	}
	names := []string{"received", "duplicate", "cancel_seal", "skipped", "call_seal", "seal_returned", "abandoned", "exited"}
	for _, row := range rows {
		b.record(row.ID, "task", names[row.Kind], nil)
		switch row.Kind {
		case taskqueue.CancelSeal:
			if b.seals.Phase(row.ID) != taskqueue.SealUnknown {
				b.check(b.seals.Cancel(row.ID))
			}
		case taskqueue.CallSeal:
			job := b.jobs[row.ID]
			b.check(b.seals.Begin(taskqueue.SealRequest{ID: row.ID, Hash: [32]byte(codec.BlockHash(job.block.Header))}))
			b.schedule(sample(b.a.n.s.rng, b.a.n.spec.Sealing.CallDelay), func() { job.callReturned = true })
		}
	}
}
func (b *sealingBuilder) sealEffects(rows []taskqueue.SealEffect, err error) {
	if !b.check(err) {
		return
	}
	names := []string{"mutex_acquired", "post_entered", "request_delivered", "post_returned", "commit_accepted", "commit_forwarded", "commit_discarded", "result_selected", "result_sent", "mutex_released"}
	for _, row := range rows {
		fields := map[string]any{}
		if row.Commit != "" {
			fields["commit_id"] = row.Commit
		}
		if row.Cancelled {
			fields["cancelled"] = true
		}
		b.record(row.ID, "seal", names[row.Kind], fields)
		switch row.Kind {
		case taskqueue.MutexAcquired:
			job := b.jobs[row.ID]
			b.schedule(sample(b.a.n.s.rng, b.a.n.spec.Sealing.PostDelay), func() { job.postReady = true })
		case taskqueue.CommitAccepted, taskqueue.CommitForwarded:
			if complete := b.completions[row.Commit]; complete != nil {
				delete(b.completions, row.Commit)
				complete(nil)
			}
			if row.Kind == taskqueue.CommitForwarded {
				_ = b.a.scheduleImport(b.blocks[row.Commit], event.PathImported)
			}
		}
	}
}
func (b *sealingBuilder) offer(req consensus.RequestBuild, wait time.Duration) {
	b.next++
	id := fmt.Sprintf("work-%d", b.next)
	job := &sealingJob{req: req, writer: b.a.n.ev, clock: b.a.n.clock}
	b.jobs[id] = job
	b.order = append(b.order, id)
	b.record(id, "callback", "scheduled", map[string]any{"wait_ns": fmt.Sprint(int64(wait))})
	b.schedule(wait, func() { b.ready = append(b.ready, id); b.record(id, "callback", "ready", nil) })
}
func (b *sealingBuilder) commit(block *types.Block, complete func(error)) {
	b.commitNext++
	id := fmt.Sprintf("commit-%d", b.commitNext)
	b.blocks[id] = block
	b.completions[id] = complete
	b.sealEffects(b.seals.OfferCommit(taskqueue.Commit{ID: id, Hash: [32]byte(codec.BlockHash(block.Header)), SealHash: [32]byte(codec.BlockHash(block.Header))}))
}
func (b *sealingBuilder) beginWork(id string) {
	b.workEffects(b.work.Accept())
	job := b.jobs[id]
	b.schedule(0, func() { b.check(b.work.ResumeProducer()) })
	if b.a.n.r == nil || !b.a.n.r.Running() {
		job.buildOutcome = taskqueue.NotRunning
	} else {
		var err error
		job.block, err = b.a.build(b.a.chain.head.Header)
		if err != nil {
			job.buildOutcome = taskqueue.AssemblyFailed
		}
	}
	samples := b.a.n.spec.BuildDelay
	if len(samples) == 0 {
		samples = b.a.n.s.sc.App.BuildDelay
	}
	b.schedule(sample(b.a.n.s.rng, samples), func() { job.buildReturned = true; b.record(id, "assembly", "returned", nil) })
}
func (b *sealingBuilder) headNotice(header *types.Header) {
	if !b.started {
		return
	}
	head := sealingHead{header: header, local: b.localPublish}
	if b.assemblerDone {
		return
	}
	if len(b.heads) < sealingHeadCapacity {
		b.heads = append(b.heads, head)
		return
	}
	b.headOffers = append(b.headOffers, head)
	if head.local {
		b.importHeadPending++
	}
	b.record("", "head", "publisher_blocked", map[string]any{"number": header.Number.String()})
}
func (b *sealingBuilder) headAccepted() {
	if len(b.headOffers) == 0 || len(b.heads) >= sealingHeadCapacity {
		return
	}
	head := b.headOffers[0]
	b.headOffers = b.headOffers[1:]
	b.heads = append(b.heads, head)
	if head.local {
		b.importHeadPending--
	}
	b.record("", "head", "publisher_accepted", map[string]any{"number": head.header.Number.String()})
}
func (b *sealingBuilder) unsubscribeHeads() {
	for _, head := range b.headOffers {
		if head.local {
			b.importHeadPending--
		}
	}
	b.headOffers = nil
	b.record("", "head", "subscription_closed", nil)
}
func (b *sealingBuilder) handleHead() {
	head := b.heads[0]
	b.heads = b.heads[1:]
	if b.a.n.alive && b.a.n.r != nil && b.a.n.r.Running() {
		b.a.n.r.NewHead(head.header)
	}
	for _, id := range b.order {
		job := b.jobs[id]
		if job.block == nil {
			continue
		}
		h := codec.BlockHash(job.block.Header)
		if index(job.block.Header)+sealingPendingAge <= index(head.header) && b.tasks.PendingID([32]byte(h)) == id {
			b.check(b.tasks.Forget([32]byte(h), id))
			b.record(id, "task", "pending_cleanup", nil)
		}
	}
	b.record("", "head", "handled", map[string]any{"number": head.header.Number.String()})
	if b.a.n.r == nil || !b.a.n.r.Running() {
		b.next++
		id := fmt.Sprintf("work-%d", b.next)
		b.jobs[id] = &sealingJob{writer: b.a.n.ev, clock: b.a.n.clock}
		b.order = append(b.order, id)
		b.workEffects(b.work.Trigger(id, taskqueue.NewHead))
	}
}
func (b *sealingBuilder) receiveResult() {
	result, err := b.seals.ReceiveResult()
	if !b.check(err) {
		return
	}
	if result.Cancelled {
		b.record(result.ID, "import", "cancelled_result_ignored", nil)
		return
	}
	block := b.blocks[result.Commit]
	if block == nil {
		b.a.n.s.violate("application_queue", b.a.n.v.address, "missing committed block")
		return
	}
	task := b.tasks.PendingID(result.SealHash)
	if task == "" {
		b.record(result.ID, "import", "pending_task_missing", nil)
		return
	}
	if stored := b.a.chain.byNum[index(block.Header)]; stored != nil && codec.BlockHash(stored.Header) == codec.BlockHash(block.Header) {
		b.record(task, "import", "known_result_ignored", nil)
		return
	}
	if index(block.Header) > b.a.head()+1 {
		b.record(task, "import", "unknown_parent", nil)
		return
	}
	b.importing = true
	b.importReturned = false
	b.schedule(b.a.importDelay(block), func() {
		b.localPublish = true
		err := b.a.importBlock(block, event.PathSealedLocally)
		b.localPublish = false
		outcome := "stored"
		if err != nil {
			outcome = "failed"
		}
		b.record(task, "import", outcome, nil)
		b.importReturned = true
	})
}
func (b *sealingBuilder) deferStop() bool {
	if b.seals.CommitBlocked() {
		b.stopRequested = true
		b.a.n.down = true
		return true
	}
	return false
}
func (b *sealingBuilder) deferStart() bool {
	if b.stopRequested || b.closing && !b.closed {
		b.restart = true
		return true
	}
	return false
}
func (b *sealingBuilder) close() {
	b.closing = true
	b.work.RequestExit()
	b.tasks.RequestExit()
	b.record("", "process", "closing", nil)
}
func (b *sealingBuilder) kill() {
	b.closed = true
	for _, timer := range b.timers {
		timer.Stop()
	}
}
func (b *sealingBuilder) finishClose() {
	restart := b.restart
	b.record("", "process", "closed", map[string]any{"unjoined_seal_owner": b.seals.Owner(), "pending_results": b.seals.ResultCount()})
	b.kill()
	if restart {
		b.a.n.start()
	}
}

// sealingApplication is an opt-in manual actor; other applications keep the
// synchronous runner contract and the pre-existing simulation behavior.
type sealingApplication struct{ *app }

func (a sealingApplication) FinalizeBlockManual(block *types.Block, _ types.Round, complete func(error)) {
	a.sealing.commit(block, complete)
}
