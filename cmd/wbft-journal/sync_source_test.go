package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func syncFixture(t *testing.T, fs fsys.FS, mode string, timer, cache bool) {
	t.Helper()
	core := journal.CoreOptions{SyncTrace: 1}
	if timer {
		core.TimerTrace = 1
	}
	if cache {
		core.CacheTrace = 1
	}
	if mode == "no-capability" {
		core.SyncTrace = 0
	}
	if mode == "future-capability" {
		core.SyncTrace = 2
	}
	j, err := journal.Open(journal.Options{FS: fs, Dir: "/sync", Synchronous: true}, journal.Identity{Self: nodeA, Run: "sync-fixture", Core: core})
	if err != nil {
		t.Fatal(err)
	}
	put := func(b any) { j.Put(journal.Record{Body: b}) }
	request := &journal.SyncRec{Stage: "requested", Request: 1, Syncing: true, Mono: 3, WallNs: 100}
	processed := &journal.SyncRec{Stage: "processed", Request: 1, Operation: 1, Syncing: true, Action: "stop", RunningBefore: true, EventsAvailable: true, EventBefore: 9, EventAfter: 11, Mono: 4, WallNs: 101}
	switch mode {
	case "missing-cursor":
		processed.EventsAvailable = false
	case "empty-boundary":
		processed.EventAfter = processed.EventBefore
		processed.Failed = true
	case "mismatched-state":
		processed.Success = true
	case "exhausted":
		processed.Operation, processed.SequenceExhausted = 0, true
	case "missing-operation":
		processed.Operation = 2
	case "missing-request-prefix":
		request.Request, processed.Request = 2, 2
	}
	// Preserve the actual enqueue order, including processing before its input.
	put(processed)
	if mode != "missing-request" {
		put(request)
	}
	if mode == "duplicate-request" {
		put(request)
	}
	if mode == "duplicate-operation" {
		put(processed)
	}
	if mode == "gap" {
		put(&journal.GapRec{Dropped: 1})
	}
	if mode == "repeated-processing" {
		put(&journal.SyncRec{Stage: "processed", Request: 1, Operation: 2, Syncing: true, Action: "none", Mono: 5, WallNs: 102})
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExportSyncRetainsEmptyFailedControlAsObservedEvidence(t *testing.T) {
	fs := fsys.NewMem()
	syncFixture(t, fs, "empty-boundary", false, false)
	if _, err := exportR01(fs, "/sync", "/out", "", ""); err != nil {
		t.Fatal(err)
	}
	rows := readFrames(t, fs, "/out/frames-sync-fixture.jsonl")
	if rows[0]["sync_trace"].(map[string]any)["complete"] != true {
		t.Fatal("observed failed call hidden", rows)
	}
	b := rows[1]["sync_control"].(map[string]any)
	if b["failed"] != true || b["events_available"] != true || b["event_before"] != b["event_after"] || b["request_source"].(map[string]any)["source_available"] != true {
		t.Fatal("failed call source lost", b)
	}
}

func TestExportSyncMarksMissingJournalPrefixIncomplete(t *testing.T) {
	fs := fsys.NewMem()
	j, err := journal.Open(journal.Options{FS: fs, Dir: "/sync", Synchronous: true, SegmentBytes: 150}, journal.Identity{Self: nodeA, Run: "retained-sync", Core: journal.CoreOptions{SyncTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(1); i <= 6; i++ {
		j.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: i, Event: "closed"}})
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := wal.Segments(fs, "/sync")
	if err != nil || len(segments) < 2 {
		t.Fatal("fixture did not rotate", segments, err)
	}
	if err := fs.Remove(filepath.Join("/sync", segments[0].Name)); err != nil {
		t.Fatal(err)
	}
	if _, err := exportR01(fs, "/sync", "/out", "", ""); err != nil {
		t.Fatal(err)
	}
	rows := readFrames(t, fs, "/out/frames-retained-sync.jsonl")
	if rows[0]["sync_trace"].(map[string]any)["complete"] != false {
		t.Fatal("retained suffix claimed complete source", rows)
	}
}

func TestExportSyncPreservesRawBoundsOrderAndSharedDeclaration(t *testing.T) {
	for _, timer := range []bool{false, true} {
		for _, cache := range []bool{false, true} {
			for _, bounded := range []bool{false, true} {
				t.Run(fmt.Sprintf("timer=%t/cache=%t/bounded=%t", timer, cache, bounded), func(t *testing.T) {
					fs := fsys.NewMem()
					syncFixture(t, fs, "repeated-processing", timer, cache)
					from, to := "", ""
					if bounded {
						from, to = "100", "110"
					}
					if _, err := exportR01(fs, "/sync", "/out", from, to); err != nil {
						t.Fatal(err)
					}
					rows := readFrames(t, fs, "/out/frames-sync-fixture.jsonl")
					seen := map[float64]bool{}
					var controls []map[string]any
					declarations := 0
					for _, row := range rows {
						seq := row["seq"].(float64)
						if seen[seq] {
							t.Fatal("raw declaration sequence duplicated", row)
						}
						seen[seq] = true
						if raw, ok := row["sync_trace"]; ok {
							declarations++
							trace := raw.(map[string]any)
							if trace["version"] != "1" || trace["requests"] != "1" || trace["operations"] != "2" || trace["complete"] != true || trace["event_cursor"] != "next_sequence" || row["clock_source"] != "unavailable" {
								t.Fatal(row)
							}
							if timer && row["scheduler_trace"] == nil || cache && row["cache_trace"] == nil {
								t.Fatal("capability lost", row)
							}
						}
						if row["type"] == "sync_control" {
							controls = append(controls, row)
						}
					}
					if declarations != 1 || len(controls) != 3 {
						t.Fatal("sync context filtered or duplicated", rows)
					}
					first := controls[0]["sync_control"].(map[string]any)
					input := controls[1]["sync_control"].(map[string]any)
					if first["stage"] != "processed" || input["stage"] != "requested" || first["event_before"] != "9" || first["event_after"] != "11" || controls[0]["t_mono_ns"] != float64(4) {
						t.Fatal("raw context changed", controls)
					}
					for _, row := range []map[string]any{controls[0], controls[2]} {
						link := row["sync_control"].(map[string]any)["request_source"].(map[string]any)
						if link["source_available"] != true || link["source_seq"] != fmt.Sprint(controls[1]["seq"]) || link["source_segment"] != fmt.Sprint(controls[1]["journal_segment"]) || link["source_offset"] != fmt.Sprint(controls[1]["journal_offset"]) {
							t.Fatal("logical request link lost", row)
						}
					}
				})
			}
		}
	}
}

func TestExportSyncIncompleteSourceNeverClaimsRequestProvenance(t *testing.T) {
	for _, mode := range []string{"gap", "missing-request", "missing-cursor", "missing-operation", "missing-request-prefix", "mismatched-state", "exhausted"} {
		t.Run(mode, func(t *testing.T) {
			fs := fsys.NewMem()
			syncFixture(t, fs, mode, false, false)
			if _, err := exportR01(fs, "/sync", "/out", "", ""); err != nil {
				t.Fatal(err)
			}
			rows := readFrames(t, fs, "/out/frames-sync-fixture.jsonl")
			for _, row := range rows {
				if trace, ok := row["sync_trace"].(map[string]any); ok && trace["complete"] != false {
					t.Fatal("incomplete trace claimed complete", row)
				}
				if control, ok := row["sync_control"].(map[string]any); ok && control["stage"] == "processed" {
					link := control["request_source"].(map[string]any)
					if link["source_available"] != false || len(link) != 1 {
						t.Fatal("invented request link", row)
					}
				}
			}
		})
	}
}

func TestExportSyncRejectsAmbiguousOrUnsupportedSource(t *testing.T) {
	for _, mode := range []string{"no-capability", "future-capability", "duplicate-request", "duplicate-operation"} {
		t.Run(mode, func(t *testing.T) {
			fs := fsys.NewMem()
			syncFixture(t, fs, mode, false, false)
			if _, err := exportR01(fs, "/sync", "/out", "", ""); err == nil {
				t.Fatal("ambiguous source accepted")
			}
		})
	}
}

func TestSyncSourceRejectsChangingJournalBetweenPasses(t *testing.T) {
	mem := fsys.NewMem()
	j, err := journal.Open(journal.Options{FS: mem, Dir: "/changing", Synchronous: true}, journal.Identity{Self: nodeA, Run: "changing-sync", Core: journal.CoreOptions{SyncTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: 1, Syncing: true}})
	if err := j.Sync(); err != nil {
		t.Fatal(err)
	}
	fs := &changingJournalFS{FS: mem, mutate: func() {
		j.Put(journal.Record{Body: &journal.SyncRec{Stage: "requested", Request: 2, Success: true}})
		if err := j.Sync(); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := exportR01(fs, "/changing", "/out", "", ""); err == nil || !strings.Contains(err.Error(), "journal changed") {
		t.Fatal("changed sync source accepted", err)
	}
}
