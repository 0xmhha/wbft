package transport

import (
	"sync"
	"testing"

	"github.com/0xmhha/wbft/types"
)

type failureEvents struct {
	mu     sync.Mutex
	events []ReceiveFailureEvent
	cache  *ReceiveFailureCache
}

func (o *failureEvents) CaptureRun() string { return "receive-failure-bookkeeping-model" }

func (o *failureEvents) ObserveReceiveFailure(e ReceiveFailureEvent) {
	if o.cache != nil {
		// Reentrant observation must not run under the functional mutex.
		_ = o.cache.Len()
	}
	o.mu.Lock()
	o.events = append(o.events, e)
	o.mu.Unlock()
}

func (o *failureEvents) snapshot() []ReceiveFailureEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ReceiveFailureEvent(nil), o.events...)
}

func failureModelSource(request uint64) ReceiveFailureSource {
	return ReceiveFailureSource{EngineRun: 1, SnapshotStep: 2, WorkerRequest: request, SnapshotPhase: ReceiveFailureStep, SnapshotHash: types.Hash{3}}
}

// These are bookkeeping API keys and model coordinates, not encoded frames
// or evidence that a signature check or network delivery actually happened.
func TestReceiveFailureCacheBoundedSourcesAndSeparation(t *testing.T) {
	observer := new(failureEvents)
	cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: 2, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	observer.cache = cache
	defer cache.Close()
	scope := NewValidationScope()
	defer scope.Close()
	context := cache.BeginContext(scope, failureModelSource(0))
	one := Inbound{Code: CodeFirst + 1, Payload: []byte("owned cache key one")}
	two := Inbound{Code: CodeFirst + 1, Payload: []byte("owned cache key two")}
	three := Inbound{Code: CodeFirst + 1, Payload: []byte("owned cache key three")}
	original := failureModelSource(10)
	ref, stored := cache.Record(context, one, ReceiveMembershipFailure, original)
	if !stored || ref.Run != observer.CaptureRun() || ref.Cache == 0 || ref.Sequence == 0 {
		t.Fatal("classified model failure was not retained with an original reference")
	}
	if duplicate, stored := cache.Record(context, one, ReceiveMembershipFailure, failureModelSource(11)); stored || duplicate != ref {
		t.Fatal("a concurrent duplicate replaced the original failure source")
	}
	if _, stored := cache.Record(context, two, ReceiveSignatureFailure, failureModelSource(12)); !stored {
		t.Fatal("second entry was not retained")
	}
	hit, ok := cache.Lookup(context, one, failureModelSource(20))
	if !ok || hit.Class != ReceiveMembershipFailure || hit.Reference != ref || hit.Source != original {
		t.Fatal("hit did not name the original classified check")
	}
	otherCode := one
	otherCode.Code++
	if _, ok := cache.Lookup(context, otherCode, failureModelSource(21)); ok {
		t.Fatal("failure key omitted the message code")
	}
	if _, stored := cache.Record(context, three, ReceiveSignatureFailure, failureModelSource(22)); !stored || cache.Len() != 2 {
		t.Fatal("entry bound changed")
	}
	if _, ok := cache.Lookup(context, two, failureModelSource(23)); ok {
		t.Fatal("LRU did not evict the least recently used key")
	}
	if _, ok := cache.Lookup(context, one, failureModelSource(24)); !ok {
		t.Fatal("recent failure disappeared")
	}
	accepted, err := NewReceiveLedger(ReceiveLedgerOptions{Pending: 4, PerPeer: 2, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.Known(scope, one.Code, one.Payload) || accepted.Recent(scope, one.Peer, one.Code, one.Payload) || accepted.Pending() != 0 {
		t.Fatal("failure bookkeeping granted accepted-cache authority")
	}
	found := false
	for _, event := range observer.snapshot() {
		if event.Action == "lookup" && event.Source.WorkerRequest == 20 {
			found = event.Hit && event.Run == ref.Run && event.Reference == ref && event.Original == original && event.Source != original && event.RequestedRun == ref.Run && event.RequestedCache == ref.Cache && event.RequestedContext == event.Context
		}
		if event.After > 2 {
			t.Fatal("observed retained count exceeded its explicit bound")
		}
	}
	if !found {
		t.Fatal("hit was not separately observed from its original failure")
	}
}

func TestReceiveFailureCachePublicationAndLifetime(t *testing.T) {
	cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: 2})
	if err != nil {
		t.Fatal(err)
	}
	scope := NewValidationScope()
	defer scope.Close()
	old := cache.BeginContext(scope, failureModelSource(0))
	in := Inbound{Code: CodeFirst + 1, Payload: []byte("intact API key")}
	if _, stored := cache.Record(old, in, ReceiveMembershipFailure, failureModelSource(1)); !stored {
		t.Fatal("initial failure missing")
	}
	nextSource := failureModelSource(0)
	nextSource.SnapshotStep++
	next := cache.BeginContext(scope, nextSource)
	if next == old || cache.Len() != 0 || !scope.Active() {
		t.Fatal("publication replacement retained keys or closed the borrowed validation scope")
	}
	if _, ok := cache.Lookup(old, in, failureModelSource(2)); ok {
		t.Fatal("old publication could hit")
	}
	if _, stored := cache.Record(old, in, ReceiveMembershipFailure, failureModelSource(3)); stored {
		t.Fatal("late old-publication check registered into its replacement")
	}
	if _, stored := cache.Record(next, in, ReceiveFailureClass(0), failureModelSource(4)); stored {
		t.Fatal("an unclassified result was retained")
	}
	if _, stored := cache.Record(next, in, ReceiveMembershipFailure, failureModelSource(5)); !stored {
		t.Fatal("new publication could not retain a failure")
	}
	scope.Close()
	if _, ok := cache.Lookup(next, in, failureModelSource(6)); ok {
		t.Fatal("closed validation scope could hit")
	}
	if _, stored := cache.Record(next, in, ReceiveMembershipFailure, failureModelSource(7)); stored {
		t.Fatal("closed validation scope registered a failure")
	}
	cache.Invalidate()
	if cache.Len() != 0 {
		t.Fatal("invalidation retained entries")
	}
	freshScope := NewValidationScope()
	defer freshScope.Close()
	if cache.BeginContext(freshScope, failureModelSource(0)) == nil {
		t.Fatal("normal new lifetime could not start")
	}
	cache.Close()
	cache.Close()
	if cache.Len() != 0 || cache.BeginContext(freshScope, failureModelSource(0)) != nil {
		t.Fatal("closed cache reopened or retained entries")
	}
}

func TestReceiveFailureCacheConcurrentPublicationReplacement(t *testing.T) {
	cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	scope := NewValidationScope()
	defer scope.Close()
	context := cache.BeginContext(scope, failureModelSource(0))
	in := Inbound{Code: CodeFirst + 1, Payload: []byte("normal bookkeeping key")}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 32 {
				cache.Record(context, in, ReceiveMembershipFailure, failureModelSource(1))
				cache.Lookup(context, in, failureModelSource(2))
			}
		})
	}
	for range 8 {
		cache.BeginContext(scope, failureModelSource(0))
	}
	workers.Wait()
	if cache.Len() > 4 {
		t.Fatal("concurrent checks exceeded capacity")
	}
	if _, stored := cache.Record(context, in, ReceiveMembershipFailure, failureModelSource(3)); stored {
		t.Fatal("superseded context was revived")
	}
}

func TestReceiveFailureCacheRejectsUnsupportedEntryLimits(t *testing.T) {
	for _, limit := range []uint64{0, InmemoryMessages + 1} {
		if cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: limit}); err == nil || cache != nil {
			t.Fatal("unsupported entry limit was accepted")
		}
	}
}

func TestReceiveFailureCacheUnavailableMetadataIsNotAuthority(t *testing.T) {
	observer := new(failureEvents)
	cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: 2, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	scope := NewValidationScope()
	defer scope.Close()
	context := cache.BeginContext(scope, ReceiveFailureSource{})
	in := Inbound{Code: CodeFirst + 1, Payload: []byte("bookkeeping only")}
	// Absent diagnostic coordinates do not grant ownership or disable normal
	// functional bookkeeping. Their absence remains explicit in the trace.
	ref, stored := cache.Record(context, in, ReceiveMembershipFailure, ReceiveFailureSource{})
	if !stored {
		t.Fatal("diagnostic absence changed functional cache ownership")
	}
	if hit, ok := cache.Lookup(context, in, ReceiveFailureSource{}); !ok || hit.Reference != ref {
		t.Fatal("functional failure disappeared with an absent diagnostic source")
	}
	for _, e := range observer.snapshot() {
		if e.Action == "context" || e.Action == "record" || e.Action == "lookup" {
			if e.Unavailable != "snapshot_source_unavailable" {
				t.Fatal("missing snapshot coordinates became available evidence")
			}
		}
	}
	context = cache.BeginContext(scope, failureModelSource(0))
	cache.Record(context, in, ReceiveMembershipFailure, failureModelSource(0))
	events := observer.snapshot()
	if events[len(events)-1].Unavailable != "worker_source_unavailable" {
		t.Fatal("missing worker request became a verified source")
	}
}

type failureNamespaceEvents struct {
	run    string
	events []ReceiveFailureEvent
}

func (o *failureNamespaceEvents) CaptureRun() string { return o.run }
func (o *failureNamespaceEvents) ObserveReceiveFailure(e ReceiveFailureEvent) {
	o.events = append(o.events, e)
}

func TestReceiveFailureCacheFreezesOriginalNamespace(t *testing.T) {
	for _, initial := range []string{"original-cache-model", ""} {
		t.Run(initial, func(t *testing.T) {
			observer := &failureNamespaceEvents{run: initial}
			cache, err := NewReceiveFailureCache(ReceiveFailureOptions{Entries: 2, Trace: observer})
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			scope := NewValidationScope()
			defer scope.Close()
			context := cache.BeginContext(scope, failureModelSource(0))
			in := Inbound{Code: CodeFirst + 1, Payload: []byte("local namespace bookkeeping")}
			ref, stored := cache.Record(context, in, ReceiveMembershipFailure, failureModelSource(1))
			if !stored || ref.Run != initial {
				t.Fatal("original namespace was not retained")
			}
			observer.run = "later-cache-model"
			hit, ok := cache.Lookup(context, in, failureModelSource(2))
			if !ok || hit.Reference != ref {
				t.Fatal("observer namespace mutation changed functional ownership")
			}
			for _, e := range observer.events {
				if e.Run != initial || e.Reference.Sequence != 0 && e.Reference.Run != initial {
					t.Fatal("an original source was rebound to a later namespace")
				}
				if initial == "" && e.Unavailable != "namespace_unavailable" {
					t.Fatal("initially unqualified evidence became available later")
				}
			}
		})
	}
}
