package runner

import (
	"bytes"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type appQueueObservations struct {
	mu      sync.Mutex
	records []journal.AppQueueRec
	inspect func()
	alter   bool
	writer  journal.Writer
}

func (o *appQueueObservations) ObserveAppQueueSource(r journal.AppQueueRec) {
	if o.inspect != nil {
		o.inspect()
	}
	copy := r
	copy.Input = bytes.Clone(r.Input)
	o.mu.Lock()
	o.records = append(o.records, copy)
	o.mu.Unlock()
	if o.writer != nil {
		o.writer.Put(journal.Record{Body: &copy})
	}
	if o.alter && len(r.Input) > 0 {
		// Only observer-owned encoded metadata changes, never a live input.
		r.Input[0] ^= 1
	}
}

func TestAppQueueObserverDetachedAfterUnlock(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	o := &appQueueObservations{alter: true}
	n.appQueueSources = o
	n.boot()
	o.inspect = func() {
		n.r.appMu.Lock()
		pending := len(n.r.appQ)
		n.r.appMu.Unlock()
		if pending > 2 {
			t.Errorf("unexpected queued inputs after observer unlock: %d", pending)
		}
	}
	n.r.PeerConnected(k.addrs[0])
	n.r.NewHead(n.chain.head)
	n.r.NewHead(n.chain.head)
	first, ok := n.r.next()
	peer, right := first.in.(consensus.PeerConnected)
	if !ok || !right || peer.Addr != k.addrs[0] {
		t.Fatal("observer changed the original queued peer", first, ok)
	}
	second, ok := n.r.next()
	head, right := second.in.(consensus.NewHead)
	if !ok || !right || head.Header != n.chain.head || len(n.r.appQ) != 0 {
		t.Fatal("observer changed normal head coalescing", second, ok)
	}
	if n.r.d.Journal != nil || len(o.records) != 5 {
		t.Fatal("diagnostic observer enabled functional recording", len(o.records))
	}
	for i, r := range o.records {
		if r.Sequence != uint64(i+1) {
			t.Fatal("original mutex order lost", r)
		}
		if _, err := inputlog.Decode(r.InputKind, r.Input, nil); err != nil {
			t.Fatal("observer changed retained bytes", err)
		}
	}
	if o.records[2].Action != "coalesce" || o.records[2].Request != 2 || o.records[3].Request != 1 || o.records[4].Request != 2 {
		t.Fatal("append identity did not survive coalescing/dequeue", o.records)
	}
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppQueueNormalCoreSourcesAndFiniteRetainedHorizon(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/app-source", Synchronous: true}, journal.Identity{Run: "app-source", Self: n.opts.Self, Mode: "diagnostic", Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit)}})
	if err != nil {
		t.Fatal(err)
	}
	n.coreSteps = &coreObservations{writer: w}
	n.appQueueSources = &appQueueObservations{writer: w}
	n.boot()
	n.r.PeerConnected(k.addrs[0])
	n.r.NewHead(n.chain.head)
	n.r.NewHead(n.chain.head)
	n.r.Pump()
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	// Public normal notification semantics also permit a queued input while
	// stopped. It is retained, not invented as a dispatched core input.
	n.r.PeerConnected(k.addrs[2])
	n.r.appMu.Lock()
	stoppedSequence := n.r.appSourceSequence
	n.r.appMu.Unlock()
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/app-source")
	if err != nil {
		t.Fatal(err)
	}
	limits := journal.AppQueueLimits{Core: journal.CoreSourceLimits{Records: 1000, Runs: 4, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20}, Operations: 100, Entries: 16, Bytes: 1 << 20}
	// Freeze the observed finite Stop horizon before invoking terminal Close.
	// Keep its original retained-input assertion on that actual prefix.
	boundary := -1
	for i, record := range records {
		if r, ok := record.Body.(*journal.AppQueueRec); ok && r.Sequence == stoppedSequence {
			boundary = i + 1
			break
		}
	}
	if boundary < 0 {
		t.Fatal("frozen stopped-time queue boundary missing")
	}
	check, err := journal.CheckAppQueueSources(records[:boundary], limits)
	if err != nil || check.Status != "consistent" || check.Appended != 3 || check.Coalesced != 1 || check.Popped != 2 || check.Clears != 1 || check.Retained != 1 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
		t.Fatal("normal source reconstruction or retained horizon changed", check, err)
	}
	check, err = journal.CheckAppQueueSources(records, limits)
	if err != nil || check.Status != "consistent" || check.Appended != 3 || check.Coalesced != 1 || check.Popped != 2 || check.Clears != 1 || check.Closes != 1 || check.Retained != 0 || check.ClearedInputs != 1 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
		t.Fatal("terminal queue closure did not dispose of actual retained work", check, err)
	}
	var terminal *journal.AppQueueRec
	for _, record := range records[boundary:] {
		if r, ok := record.Body.(*journal.AppQueueRec); ok {
			if terminal != nil || r.Action != "close" || r.Version != journal.AppQueueCloseSourceVersion || r.Before != 1 || r.After != 0 {
				t.Fatal("unexpected queue operation after frozen finite horizon", r)
			}
			terminal = r
		}
	}
	if terminal == nil {
		t.Fatal("terminal queue source missing")
	}
	// These are independent, offline metadata copies. No live input, WAL or
	// original transcript is changed to exercise the strict source checker.
	duplicate := *terminal
	duplicate.Sequence++
	copies := append(append([]journal.Record(nil), records...), journal.Record{Body: &duplicate})
	check, err = journal.CheckAppQueueSources(copies, limits)
	if err == nil || check.Status != "inconsistent" || check.Reason != "application_queue_mutation_after_close" {
		t.Fatal("duplicate terminal closure accepted", check, err)
	}
	missingClear := make([]journal.Record, 0, len(records))
	for _, record := range records {
		if r, ok := record.Body.(*journal.AppQueueRec); ok && r.Action == "clear" {
			continue
		}
		missingClear = append(missingClear, record)
	}
	check, err = journal.CheckAppQueueSources(missingClear, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "application_queue_sequence_gap" {
		t.Fatal("missing Stop clear did not preserve its actual source gap", check, err)
	}
}

func TestAppQueueObserverConcurrentNormalNotifications(t *testing.T) {
	o := new(appQueueObservations)
	r := &Runner{d: Deps{Clock: SystemClock(), AppQueueSources: o}, notify: make(chan struct{}, 1)}
	o.inspect = func() {
		r.appMu.Lock()
		pending := len(r.appQ)
		r.appMu.Unlock()
		if pending < 1 || pending > 4 {
			t.Errorf("unexpected concurrent queue state after observer unlock: %d", pending)
		}
	}
	var producers sync.WaitGroup
	for i := range 4 {
		producers.Go(func() { r.PeerConnected(types.Address{byte(i + 1)}) })
	}
	producers.Wait()
	if len(o.records) != 4 || len(r.appQ) != 4 {
		t.Fatal("normal concurrent notification lost", len(o.records), len(r.appQ))
	}
	seen := map[uint64]bool{}
	for _, rec := range o.records {
		if seen[rec.Sequence] || rec.Sequence == 0 || rec.Request != rec.Sequence || rec.Before+1 != rec.After {
			t.Fatal("source did not preserve original mutex coordinates", rec)
		}
		seen[rec.Sequence] = true
	}
}

func TestAppQueueObserverMetadataExhaustionKeepsNotifications(t *testing.T) {
	o := new(appQueueObservations)
	r := &Runner{d: Deps{Clock: &manualClock{}, AppQueueSources: o}, notify: make(chan struct{}, 1), appSourceSequence: ^uint64(0) - 1}
	for i := range 3 {
		r.PeerConnected(types.Address{byte(i + 1)})
	}
	if len(r.appQ) != 3 || o.records[0].Sequence != ^uint64(0) {
		t.Fatal("diagnostic counter affected normal notifications")
	}
	for _, rec := range o.records[1:] {
		if rec.Sequence != 0 || rec.Request != 0 || rec.Unavailable != "metadata_exhausted" {
			t.Fatal("exhausted source identity reused", rec)
		}
	}
}
