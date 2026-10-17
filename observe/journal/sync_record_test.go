package journal

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestSyncControlRecordsRoundTrip(t *testing.T) {
	for _, record := range []*SyncRec{
		{Stage: "requested", Request: 1, Syncing: true, Mono: 5, WallNs: 99},
		{Stage: "processed", Request: 1, Operation: 1, Syncing: true, Action: "stop", RunningBefore: true, EventsAvailable: true, EventBefore: 3, EventAfter: 4, Mono: 6, WallNs: 100},
		{Stage: "processed", Request: 2, Operation: 2, Success: true, FirstAfter: true, Action: "start", RunningAfter: true, EventsAvailable: true, EventBefore: 8, EventAfter: 9, Mono: 9, WallNs: 110},
		{Stage: "processed", Action: "none", RunningBefore: true, RunningAfter: true, SequenceExhausted: true, Mono: 10, WallNs: 111},
	} {
		raw, err := encodeBody(Record{Body: record}, 17)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindSync, raw)
		if err != nil || decoded.JSeq != 17 || decoded.Kind != KindSync {
			t.Fatalf("decoded %v: %v", decoded, err)
		}
		if *decoded.Body.(*SyncRec) != *record {
			t.Fatalf("observation changed: %+v", decoded.Body)
		}
		again, err := encodeBody(decoded, 17)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatalf("record bytes changed: %v", err)
		}
	}
}

func TestSyncControlRecordRejectsMalformedWire(t *testing.T) {
	valid := &SyncRec{Stage: "processed", Request: 3, Operation: 4, Action: "none", EventsAvailable: true, EventBefore: 7, EventAfter: 8, Mono: 9}
	raw, err := encodeBody(Record{Body: valid}, 2)
	if err != nil {
		t.Fatal(err)
	}
	var wire syncRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*syncRLP){
		func(r *syncRLP) { r.Format++ }, func(r *syncRLP) { r.Stage = "guessed" },
		func(r *syncRLP) { r.Action = "guessed" }, func(r *syncRLP) { r.Mono = ^uint64(0) },
		func(r *syncRLP) { r.Syncing = 2 }, func(r *syncRLP) { r.Success = 2 },
		func(r *syncRLP) { r.FirstBefore = 2 }, func(r *syncRLP) { r.FirstAfter = 2 },
		func(r *syncRLP) { r.RunningBefore = 2 }, func(r *syncRLP) { r.RunningAfter = 2 },
		func(r *syncRLP) { r.Failed = 2 }, func(r *syncRLP) { r.EventsAvailable = 2 },
		func(r *syncRLP) { r.SequenceExhausted = 2 }, func(r *syncRLP) { r.EventAfter = 6 },
		func(r *syncRLP) { r.Stage = "requested" },
	} {
		bad := wire
		change(&bad)
		raw, err := rlp.Encode(&bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindSync, raw); err == nil {
			t.Fatalf("malformed observation accepted: %+v", bad)
		}
	}
	if _, err := encodeBody(Record{Body: (*SyncRec)(nil)}, 1); err == nil {
		t.Fatal("nil observation accepted")
	}
}

func TestSyncObservationQueueBudgetPreservesGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/sync", QueueRecords: 10, QueueBytes: 128}, ident())
	if err != nil {
		t.Fatal(err)
	}
	w.Put(Record{Body: &SyncRec{Stage: "requested", Request: 1, Syncing: true, Mono: 7}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/sync")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if _, ok := record.Body.(*SyncRec); ok {
			t.Fatal("sync observation exceeded the queue byte budget")
		}
		if gap, ok := record.Body.(*GapRec); ok {
			if gap.Dropped != 1 || len(gap.ByKind) != 1 || gap.ByKind[0].Kind != uint64(KindSync) || gap.ByKind[0].Count != 1 || gap.FirstMono != 7 || gap.LastMono != 7 {
				t.Fatalf("overflow evidence changed: %+v", gap)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing sync queue-overflow evidence")
	}
}

func TestOriginalSegmentWithoutSyncMetadataRoundTrips(t *testing.T) {
	// Written by the unchanged 7f94990 baseline with timer/cache trace
	// versions enabled. The fixture predates the optional sync trace field.
	text, err := os.ReadFile("testdata/sync-legacy-segment.hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeBody(KindSegment, raw)
	if err != nil {
		t.Fatal(err)
	}
	header := record.Body.(*SegmentRec)
	if header.Run != "legacy-sync-fixture" || header.Core.TimerTrace != 1 || header.Core.CacheTrace != 1 || header.Core.SyncTrace != 0 {
		t.Fatalf("legacy metadata changed: %+v", header)
	}
	again, err := encodeBody(record, record.JSeq)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("old segment bytes changed: %v", err)
	}
	header.Core.SyncTrace = SyncTraceVersion
	updated, err := encodeBody(record, record.JSeq)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindSegment, updated)
	if err != nil || decoded.Body.(*SegmentRec).Core.SyncTrace != SyncTraceVersion {
		t.Fatalf("new segment metadata missing: %v", err)
	}
}
