package runner

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type closeQueueSources struct {
	appQueueObservations
	stopped chan struct{}
}

func (*closeQueueSources) CaptureRun() string { return "close-source" }

func (o *closeQueueSources) ObserveAppQueueSource(r journal.AppQueueRec) {
	o.appQueueObservations.ObserveAppQueueSource(r)
	if r.Action == "clear" {
		o.stopped <- struct{}{}
	}
}

type closeNormalApp struct {
	*normalCallApp
	build chan consensus.RequestBuild
}

func (a *closeNormalApp) ReadyToBuild(req consensus.RequestBuild, _ time.Duration, _ <-chan struct{}) {
	select {
	case a.build <- req:
	default:
	}
}

func TestAppQueueCloseJoinsNormalInFlightFinalization(t *testing.T) {
	k := newKeys(t, 1)
	n := newTNode(t, k, 0)
	clock := SystemClock()
	n.chain.clock = clock
	n.app.onFinal = func(b *types.Block) {
		n.chain.mu.Lock()
		n.chain.head = b.Header
		n.chain.mu.Unlock()
	}
	app := &closeNormalApp{normalCallApp: &normalCallApp{fakeApp: n.app, entered: make(chan struct{}), resume: make(chan struct{})}, build: make(chan consensus.RequestBuild, 1)}
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/close-source", Synchronous: true}, journal.Identity{Run: "close-source", Self: n.opts.Self, Mode: "diagnostic", Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit)}})
	if err != nil {
		t.Fatal(err)
	}
	inputs := &closeQueueSources{appQueueObservations: appQueueObservations{writer: w}, stopped: make(chan struct{}, 1)}
	finalized := &notifyingFinalizeSources{done: make(chan journal.FinalizeRec, 1)}
	r, err := New(Config{Core: n.opts}, Deps{Chain: n.chain, App: app, Clock: clock, Signer: mustSigner(t, k, 0), CoreSteps: &coreObservations{writer: w}, AppQueueSources: inputs, FinalizeSources: finalized})
	if err != nil {
		t.Fatal(err)
	}
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(app.resume) })
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-app.build:
	case <-time.After(5 * time.Second):
		t.Fatal("normal proposer did not request a block")
	}
	b := block(t, 10, 0, k.addrs[0], codec.BlockHash(n.chain.Head()))
	r.Submit(b)
	select {
	case <-app.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("normal self-quorum did not call the application")
	}
	closed := make(chan error, 3)
	for range 3 {
		go func() { closed <- r.Close() }()
	}
	select {
	case <-inputs.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("normal Close did not execute its original Stop clear")
	}
	// A normal application call remains in flight during graceful shutdown.
	// Public notifications must stop admission, while its real return and
	// CommitResult append remain visible until the terminal join boundary.
	r.appMu.Lock()
	sequence, pending, closing := r.appSourceSequence, len(r.appQ), r.appClosing
	r.appMu.Unlock()
	if !closing || pending != 0 {
		t.Fatal("Close did not gate notifications after the original Stop", closing, pending)
	}
	r.Submit(b)
	r.NewHead(n.chain.Head())
	r.PeerConnected(k.addrs[0])
	r.appMu.Lock()
	unchanged := r.appSourceSequence == sequence && len(r.appQ) == pending
	r.appMu.Unlock()
	if !unchanged {
		t.Fatal("notification admitted after Close acceptance")
	}
	release.Do(func() { close(app.resume) })
	for range 3 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("normal Close did not join the successful application call")
		}
	}
	var result journal.FinalizeRec
	select {
	case result = <-finalized.done:
	case <-time.After(5 * time.Second):
		t.Fatal("normal completion notification source missing")
	}
	if result.HasError || result.Action != "notify" || result.QueueRequest == 0 || len(n.app.finalized) != 1 {
		t.Fatal("successful application return or original notification lost", result)
	}
	r.appMu.Lock()
	if len(r.appQ) != 0 || r.headNote != nil || !r.appQueueClosed {
		t.Error("terminal Close retained actual application inputs")
	}
	sequence = r.appSourceSequence
	r.appMu.Unlock()
	r.Submit(b)
	r.NewHead(n.chain.Head())
	r.PeerConnected(k.addrs[0])
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r.appMu.Lock()
	unchanged = r.appSourceSequence == sequence && len(r.appQ) == 0
	r.appMu.Unlock()
	if !unchanged {
		t.Fatal("closed API or repeated Close changed terminal sequence")
	}
	items := slices.Clone(inputs.records)
	slices.SortFunc(items, func(a, b journal.AppQueueRec) int {
		if a.Sequence < b.Sequence {
			return -1
		}
		if a.Sequence > b.Sequence {
			return 1
		}
		return 0
	})
	if len(items) < 3 {
		t.Fatal("normal closure source tail missing", items)
	}
	tail := items[len(items)-3:]
	if tail[0].Action != "clear" || tail[0].Version != 1 || tail[1].Action != "append" || tail[1].InputKind != inputlog.KindCommitResult || tail[2].Action != "close" || tail[2].Version != 2 || tail[2].Before != 1 || tail[2].After != 0 {
		t.Fatal("normal completion was hidden or terminal closure came before its join", tail)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/close-source")
	if err != nil {
		t.Fatal(err)
	}
	limits := journal.AppQueueLimits{Core: journal.CoreSourceLimits{Records: 1000, Runs: 4, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20}, Operations: 100, Entries: 16, Bytes: 1 << 20}
	check, err := journal.CheckAppQueueSources(records, limits)
	if err != nil || check.Status != "consistent" || check.Clears != 1 || check.Closes != 1 || check.Retained != 0 || check.ClearedInputs != 1 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
		t.Fatal("independent original core/queue sources did not verify terminal closure", check, err)
	}
}

func TestAppQueueNeverStartedCloseAndMetadataExhaustion(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		o := new(appQueueObservations)
		r := &Runner{d: Deps{Clock: SystemClock(), AppQueueSources: o}, notify: make(chan struct{}, 1)}
		r.NewHead(&types.Header{})
		if exhausted {
			r.appSourceSequence = ^uint64(0)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		last := o.records[len(o.records)-1]
		want := "stop_source_missing"
		if exhausted {
			want = "metadata_exhausted"
		}
		if len(r.appQ) != 0 || r.headNote != nil || last.Action != "close" || last.Version != 2 || last.Unavailable != want || last.EngineRun != 0 || last.Step != 0 {
			t.Fatal("never-started closure invented a Stop source or retained work", last)
		}
		before := len(o.records)
		r.PeerConnected(types.Address{1})
		if err := r.Close(); err != nil || len(o.records) != before {
			t.Fatal("never-started repeated Close or notification changed terminal boundary", err)
		}
	}
}
