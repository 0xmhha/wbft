package runner

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type finalizeObservations struct {
	mu      sync.Mutex
	records []journal.FinalizeRec
	inspect func()
	alter   bool
}

func (o *finalizeObservations) ObserveFinalizeSource(r journal.FinalizeRec) {
	if o.inspect != nil {
		o.inspect()
	}
	copy := r
	copy.Arguments = bytes.Clone(r.Arguments)
	copy.Input = bytes.Clone(r.Input)
	o.mu.Lock()
	o.records = append(o.records, copy)
	o.mu.Unlock()
	if o.alter && len(r.Arguments) > 0 {
		r.Arguments[0] ^= 1
	}
	if o.alter && len(r.Input) > 0 {
		r.Input[0] ^= 1
	}
}

type namedAppSources struct{ appQueueObservations }

func (*namedAppSources) CaptureRun() string { return "original-app-writer" }

func TestFinalizeObserverDetachedAndOriginalAppendCoordinate(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	o := &finalizeObservations{alter: true}
	n.finalizeSources = o
	app := new(namedAppSources)
	n.appQueueSources = app
	n.boot()
	o.inspect = func() {
		n.r.commitMu.Lock()
		pending := len(n.r.commitQ)
		n.r.commitMu.Unlock()
		n.r.appMu.Lock()
		inputs := len(n.r.appQ)
		n.r.appMu.Unlock()
		n.r.finalizeSourceMu.Lock()
		sequence := n.r.finalizeSourceSequence
		n.r.finalizeSourceMu.Unlock()
		if pending > 1 || inputs > 1 || sequence == 0 {
			t.Error("source callback did not observe original normal queues", pending, inputs, sequence)
		}
	}
	b := block(t, 10, 0, k.addrs[0], types.Hash{})
	// Exercise the normal output executor and application call contract. The
	// source checker separately verifies real consensus outputs in simulation.
	n.r.commit(&stepCtx{step: 7}, consensus.Commit{Block: b}, 3)
	if !n.r.commitOne() || len(n.app.finalized) != 1 || len(o.records) != 5 {
		t.Fatal("normal finalization changed", len(o.records))
	}
	for i, r := range o.records {
		if r.Sequence != uint64(i+1) || r.Task != 1 || r.EngineRun != n.r.engineRun || r.Step != 7 || r.Output != 3 || r.Unavailable != "" {
			t.Fatal("original task identity changed", r)
		}
	}
	last := o.records[4]
	if last.Action != "notify" || last.QueueRun != "original-app-writer" || last.QueueRequest != 1 || !bytes.Equal(last.Input, app.records[0].Input) {
		t.Fatal("notification borrowed a different append", last)
	}
	if !bytes.Equal(o.records[0].Arguments, o.records[2].Arguments) || n.r.d.Journal != nil {
		t.Fatal("observer affected call bytes or functional journal")
	}
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeMetadataRetainsOriginalOwnerAndStickyExhaustion(t *testing.T) {
	// Metadata-only fixture: no live core, application call, input or fault runs.
	o := new(finalizeObservations)
	r := &Runner{d: Deps{Clock: SystemClock(), FinalizeSources: o}, engineRun: 99, finalizeSourceSequence: 9}
	j := commitJob{source: finalizeSourceOwner{engine: 1, step: 2, output: 3, task: 4}}
	rec := r.finalizeSource("return", j, 0, 0, false, "", nil)
	if rec.EngineRun != 1 || rec.Step != 2 || rec.Output != 3 || rec.Task != 4 || rec.Sequence != 10 || rec.Unavailable != "" {
		t.Fatal("late completion borrowed current engine", rec)
	}
	r.finalizeSourceSequence = ^uint64(0) - 1
	last := r.finalizeSource("return", j, 0, 0, false, "", nil)
	exhausted := r.finalizeSource("return", j, 0, 0, false, "", nil)
	again := r.finalizeSource("return", j, 0, 0, false, "", nil)
	if last.Sequence != ^uint64(0) || last.Unavailable != "" || exhausted.Sequence != 0 || again.Sequence != 0 || exhausted.Unavailable != "metadata_exhausted" || again.Unavailable != "metadata_exhausted" {
		t.Fatal("diagnostic identity wrapped", last, exhausted, again)
	}
	off := &Runner{}
	if off.finalizeSource("enqueue", commitJob{}, 0, 1, false, "", nil) != nil {
		t.Fatal("disabled hook encoded arguments")
	}
}

type normalCallApp struct {
	*fakeApp
	entered chan struct{}
	resume  chan struct{}
}

func (a *normalCallApp) FinalizeBlock(b *types.Block, round types.Round) error {
	close(a.entered)
	<-a.resume
	return a.fakeApp.FinalizeBlock(b, round)
}

type notifyingFinalizeSources struct {
	finalizeObservations
	done chan journal.FinalizeRec
}

func (o *notifyingFinalizeSources) ObserveFinalizeSource(r journal.FinalizeRec) {
	o.finalizeObservations.ObserveFinalizeSource(r)
	if r.Action == "notify" {
		o.done <- r
	}
}

func TestFinalizeObserverNormalCallCompletesAcrossEngineRestart(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	clock := SystemClock()
	n.chain.clock = clock
	app := &normalCallApp{fakeApp: n.app, entered: make(chan struct{}), resume: make(chan struct{})}
	sources := &notifyingFinalizeSources{done: make(chan journal.FinalizeRec, 1)}
	inputs := new(namedAppSources)
	r, err := New(Config{Core: n.opts}, Deps{Chain: n.chain, App: app, Clock: clock, Signer: mustSigner(t, k, 1), FinalizeSources: sources, AppQueueSources: inputs})
	if err != nil {
		t.Fatal(err)
	}
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(app.resume) })
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	b := block(t, 10, 0, k.addrs[0], types.Hash{})
	// The existing normal commit executor owns the task. The application
	// returns success after an ordinary operator Stop/Start, without a fault
	// command, altered clock or modified consensus input.
	r.commit(&stepCtx{step: 7}, consensus.Commit{Block: b}, 3)
	select {
	case <-app.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("normal application call did not start")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	release.Do(func() { close(app.resume) })
	select {
	case result := <-sources.done:
		if result.EngineRun != 1 || result.Step != 7 || result.Output != 3 || result.Task != 1 || result.QueueRun != "original-app-writer" || result.QueueRequest == 0 || result.HasError || result.Unavailable != "" {
			t.Fatal("late normal completion lost its original task", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normal application completion lost")
	}
	if len(n.app.finalized) != 1 {
		t.Fatal("normal finalization did not execute once")
	}
}
