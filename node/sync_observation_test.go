package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func waitSyncRecord(t *testing.T, n *Node, fs fsys.FS, after uint64) *journal.SyncRec {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	var lastRecords []journal.Record
	for time.Now().Before(deadline) {
		// The journal normally batches buffered writes. Flush for this test's
		// read-only observation; do not replace the production queue policy.
		if err := n.journal.Sync(); err != nil {
			t.Fatal(err)
		}
		records, err := journal.ReadAll(fs, "/data/"+journalDir)
		lastErr, lastRecords = err, records
		if err == nil {
			for _, record := range records {
				if r, ok := record.Body.(*journal.SyncRec); ok && r.Stage == "processed" && r.Operation > after {
					return r
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("sync control observation was not written after %d: error=%v records=%+v", after, lastErr, lastRecords)
	return nil
}

// Actual runner controls are linked without deriving their bounds from clocks.
// A failed first sync permits a retry; later syncs preserve the running engine.
func TestSyncObservationActualControlsAndRepeatedWake(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a, fs, events := newTestApp(cj, g), fsys.NewMem(), &syncBuffer{}
	n := startNode(t, a, fs, key, false, events)
	t.Cleanup(func() { stop(t, n) })
	states := []app.SyncState{{Syncing: true}, {}, {Syncing: true}, {Success: true}, {Syncing: true}, {Success: true}}
	actions := []string{"stop", "start", "stop", "start", "none", "none"}
	var observed []*journal.SyncRec
	var operation uint64
	for i, state := range states {
		a.cons.OnSyncState(state)
		r := waitSyncRecord(t, n, fs, operation)
		operation = r.Operation
		if r.Request != uint64(i+1) || r.Syncing != state.Syncing || r.Success != state.Success || r.Action != actions[i] || r.Failed || r.SequenceExhausted {
			t.Fatalf("control %d: %+v", i, r)
		}
		if r.FirstBefore != (i >= 4) || r.FirstAfter != (i >= 3) {
			t.Fatalf("first-success guard %d: %+v", i, r)
		}
		if r.Action == "none" {
			if r.EventsAvailable || r.EventBefore != 0 || r.EventAfter != 0 || !r.RunningBefore || !r.RunningAfter {
				t.Fatalf("invented control boundary: %+v", r)
			}
		} else if !r.EventsAvailable || r.EventAfter <= r.EventBefore || r.RunningBefore == r.RunningAfter {
			t.Fatalf("actual control boundary missing: %+v", r)
		}
		observed = append(observed, r)
	}
	n.syncWake <- struct{}{}
	repeat := waitSyncRecord(t, n, fs, operation)
	if repeat.Request != 6 || repeat.Operation != operation+1 || repeat.Action != "none" {
		t.Fatalf("repeated handling was hidden: %+v", repeat)
	}
	stop(t, n)
	for i, r := range observed[:4] {
		want := "ENGINE_STOP"
		if i%2 == 1 {
			want = "ENGINE_START"
		}
		count := 0
		for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
			var row struct {
				Seq  uint64 `json:"seq"`
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if row.Seq >= r.EventBefore && row.Seq < r.EventAfter && row.Kind == want {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("control %d contains %d actual %s records: %+v", i, count, want, r)
		}
	}
	records, err := journal.ReadAll(fs, "/data/"+journalDir)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	for _, record := range records {
		if s, ok := record.Body.(*journal.SegmentRec); ok && s.Core.SyncTrace != journal.SyncTraceVersion {
			t.Fatal("sync trace not declared")
		}
		if r, ok := record.Body.(*journal.SyncRec); ok && r.Stage == "requested" {
			requests++
		}
	}
	if requests != len(states) {
		t.Fatalf("request observations: %d", requests)
	}
}

func TestSyncObservationPreservesCoalescingAndSequenceExhaustion(t *testing.T) {
	fs := fsys.NewMem()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/sync", Synchronous: true}, journal.Identity{Run: "coalesced", Core: journal.CoreOptions{SyncTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{state: started, journal: w, clock: runner.SystemClock(), syncWake: make(chan struct{}, 1)}
	s := &service{n: n}
	s.OnSyncState(app.SyncState{Syncing: true})
	s.OnSyncState(app.SyncState{})
	s.OnSyncState(app.SyncState{Success: true})
	if len(n.syncWake) != 1 || n.syncRequest != 3 || !n.syncLatest.Success {
		t.Fatal("latest-state coalescing changed")
	}
	n.syncRequests = ^uint64(0) - 1
	s.OnSyncState(app.SyncState{})
	s.OnSyncState(app.SyncState{Syncing: true})
	s.OnSyncState(app.SyncState{Success: true})
	if n.syncRequest != 0 || n.syncRequests != ^uint64(0) {
		t.Fatal("sequence wrapped")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(fs, "/sync")
	if err != nil {
		t.Fatal(err)
	}
	var requests []*journal.SyncRec
	for _, record := range records {
		if r, ok := record.Body.(*journal.SyncRec); ok {
			requests = append(requests, r)
		}
	}
	if len(requests) != 6 || requests[3].Request != ^uint64(0) || requests[3].SequenceExhausted || !requests[4].SequenceExhausted || !requests[5].SequenceExhausted {
		t.Fatal(requests)
	}
}

func TestSyncObservationRetainsFailedControlWithoutLifecycleEvent(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a, fs, events := newTestApp(cj, g), fsys.NewMem(), &syncBuffer{}
	n := startNode(t, a, fs, key, false, events)
	t.Cleanup(func() { stop(t, n) })
	if err := n.Runner().Close(); err != nil {
		t.Fatal(err)
	}
	a.cons.OnSyncState(app.SyncState{Success: true})
	r := waitSyncRecord(t, n, fs, 0)
	if r.Action != "start" || !r.Failed || r.RunningBefore || r.RunningAfter || !r.EventsAvailable || r.EventAfter < r.EventBefore || !r.FirstAfter {
		t.Fatalf("failed start was hidden or fabricated an event: %+v", r)
	}
	stop(t, n)
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var row struct {
			Seq  uint64 `json:"seq"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		// An unrelated asynchronous record can occur during a failed call.
		// Its real cursor range must not be replaced by an invented empty one.
		if row.Seq >= r.EventBefore && row.Seq < r.EventAfter && row.Kind == "ENGINE_START" {
			t.Fatalf("closed runner unexpectedly started: %s", line)
		}
	}
}
