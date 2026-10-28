package journal

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type failureCodecEvents struct {
	events []transport.ReceiveFailureEvent
}

func (o *failureCodecEvents) CaptureRun() string { return "failure-codec-model" }
func (o *failureCodecEvents) ObserveReceiveFailure(e transport.ReceiveFailureEvent) {
	o.events = append(o.events, e)
}

func failureCodecSource(request uint64) transport.ReceiveFailureSource {
	return transport.ReceiveFailureSource{EngineRun: 1, SnapshotStep: 2, WorkerRequest: request, SnapshotPhase: transport.ReceiveFailureStep, SnapshotHash: types.Hash{7}}
}

// Coordinates here are a bookkeeping codec model, not verifier or socket proof.
func failureCodecModel(t *testing.T) ([]transport.ReceiveFailureEvent, transport.ReceiveFailureHit) {
	t.Helper()
	observer := new(failureCodecEvents)
	cache, err := transport.NewReceiveFailureCache(transport.ReceiveFailureOptions{Entries: 2, Trace: observer})
	if err != nil {
		t.Fatal(err)
	}
	scope := transport.NewValidationScope()
	defer scope.Close()
	context := cache.BeginContext(scope, failureCodecSource(0))
	in := transport.Inbound{Code: transport.CodeFirst + 1, Payload: []byte("codec model key")}
	if _, ok := cache.Lookup(context, in, failureCodecSource(1)); ok {
		t.Fatal("new cache was already populated")
	}
	if _, stored := cache.Record(context, in, transport.ReceiveMembershipFailure, failureCodecSource(2)); !stored {
		t.Fatal("model failure was not retained")
	}
	hit, ok := cache.Lookup(context, in, failureCodecSource(3))
	if !ok || hit.Lookup.Sequence <= hit.Reference.Sequence {
		t.Fatal("lookup did not retain a separate operation reference")
	}
	cache.Invalidate()
	cache.Close()
	return observer.events, hit
}

func TestReceiveFailureRecordModelRoundTripAndWriter(t *testing.T) {
	events, _ := failureCodecModel(t)
	id := ident()
	id.Run = "failure-codec-model"
	id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
	id.Core.CachePolicy = failureDeclarationPolicy()
	id.Core.ReceiveFailureCache = &ReceiveFailureCacheOptions{Profile: ReceiveFailureCacheProfile, Entries: 2}
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/failure-records", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	for index, event := range events {
		body := &ReceiveFailureCacheRec{Version: ReceiveFailureRecordVersion, Transition: event, Mono: time.Duration(index + 1), WallNs: int64(10 + index)}
		row := Record{Body: body}
		raw, err := encodeBody(row, uint64(index+2))
		if err != nil {
			t.Fatalf("cache action %s failed encoding: %v", event.Action, err)
		}
		decoded, err := decodeBody(KindReceiveFailure, raw)
		if err != nil || !reflect.DeepEqual(decoded.Body, body) {
			t.Fatal("failure cache operation changed in codec", event.Action, err)
		}
		if kind, ok := kindOf(body); !ok || kind != KindReceiveFailure || kind.String() != "receive_failure_cache" || size(row) < int64(len(raw)) {
			t.Fatal("new cache kind or byte accounting missing")
		}
		w.Put(row)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/failure-records")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, record := range records {
		if _, ok := record.Body.(*ReceiveFailureCacheRec); ok {
			count++
		}
	}
	if count != len(events) {
		t.Fatal("writer/reader lost new cache operations", count, len(events))
	}
}

func TestInboxFailureHitHasSeparateKindAndOriginalReference(t *testing.T) {
	_, hit := failureCodecModel(t)
	body := &InboxFailureHitRec{Version: ReceiveFailureRecordVersion, Source: InboxRec{Version: InboxSourceVersion, Sequence: 5, Request: 1, Action: "failure_hit", Result: "membership", SnapshotEngine: 1, SnapshotStep: 2, SnapshotPhase: "step", SnapshotContextHash: types.Hash{7}, Code: transport.CodeFirst + 1, Order: []types.Address{{1}}, Mono: 8, WallNs: 20}, Lookup: hit.Lookup, Original: hit.Reference, Class: hit.Class}
	raw, err := encodeBody(Record{Body: body}, 10)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindInboxFailureHit, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Body.(*InboxFailureHitRec)
	again, err := encodeBody(decoded, 10)
	if err != nil || !bytes.Equal(raw, again) || got.Source.Action != "failure_hit" || got.Lookup != hit.Lookup || got.Original != hit.Reference || got.Source.Signer != (types.Address{}) {
		t.Fatal("hit became a verifier result or lost original provenance", err)
	}
	if _, err := encodeInboxRec(&body.Source, 10); err == nil {
		t.Fatal("hit was accepted as an old executed inbox check")
	}
	if _, err := decodeBody(KindInbox, raw); err == nil {
		t.Fatal("new hit wire was accepted as an old inbox kind")
	}
	if kind, ok := kindOf(body); !ok || kind != KindInboxFailureHit || kind.String() != "inbox_failure_hit" || size(Record{Body: body}) < int64(len(raw)) || monoOf(Record{Body: body}) != 8 {
		t.Fatal("new hit kind or bounds missing")
	}
}

func TestReceiveFailureRecordsRequireExplicitSourceSupport(t *testing.T) {
	events, _ := failureCodecModel(t)
	id := ident()
	id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
	limits := CoreSourceLimits{Records: 100, Runs: 4, Steps: 100, Environments: 100, Outputs: 100, Bytes: 1 << 20}
	check, err := CheckCoreStepSources([]Record{{Body: &SegmentRec{Identity: id}}, {Body: &ReceiveFailureCacheRec{Version: ReceiveFailureRecordVersion, Transition: events[0]}}}, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "receive_failure_source_profile_unavailable" {
		t.Fatal("old source inspector ignored a new record without a declaration", check, err)
	}
}

// This exercises detached codec metadata only. No changed field reaches an
// inbox, verifier, network frame, or running journal.
func TestInboxFailureHitWallTimeRange(t *testing.T) {
	_, hit := failureCodecModel(t)
	body := &InboxFailureHitRec{Version: ReceiveFailureRecordVersion, Source: InboxRec{Version: InboxSourceVersion, Sequence: 5, Request: 1, Action: "failure_hit", Result: "membership", SnapshotEngine: 1, SnapshotStep: 2, SnapshotPhase: "step", SnapshotContextHash: types.Hash{7}, Code: transport.CodeFirst + 1, WallNs: math.MaxInt64}, Lookup: hit.Lookup, Original: hit.Reference, Class: hit.Class}
	raw, err := encodeInboxFailureHit(body, 10)
	if err != nil {
		t.Fatal("valid signed wall-time bound refused", err)
	}
	if _, err := decodeInboxFailureHit(raw); err != nil {
		t.Fatal("valid wall-time bound failed decoding", err)
	}
	body.Source.WallNs++
	if _, err := encodeInboxFailureHit(body, 10); err == nil {
		t.Fatal("detached metadata exceeded journal's signed time range")
	}
}

func TestReceiveFailureRecordGapKeepsNewKind(t *testing.T) {
	events, _ := failureCodecModel(t)
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/failure-gap", QueueBytes: 1, QueueRecords: 1}, ident())
	if err != nil {
		t.Fatal(err)
	}
	w.Put(Record{Body: &ReceiveFailureCacheRec{Version: ReceiveFailureRecordVersion, Transition: events[0], Mono: 7, WallNs: 9}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/failure-gap")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindReceiveFailure) && kind.Count == 1 && gap.FirstMono == 7 && gap.LastMono == 7 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("dropped new cache operation became an unclassified gap")
	}
}
