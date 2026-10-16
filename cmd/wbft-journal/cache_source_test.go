package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"strings"
	"testing"
)

func cacheFixture(t *testing.T, fs fsys.FS, mode string) {
	t.Helper()
	trace := journal.CacheTraceVersion
	if mode == "no-capability" {
		trace = 0
	}
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/cache", Synchronous: true}, journal.Identity{Self: nodeA, Run: "cache-fixture", Core: journal.CoreOptions{CacheTrace: trace, TimerTrace: func() uint64 {
		if mode == "with-scheduler" {
			return journal.TimerTraceVersion
		}
		return 0
	}()}})
	if err != nil {
		t.Fatal(err)
	}
	put := func(b any) { w.Put(journal.Record{Body: b}) }
	payload := []byte{0xc0}
	key := codec.DedupKey(payload)
	sum := types.Hash(sha256.Sum256(payload))
	put(&journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"})
	put(&journal.CacheRec{Instance: 1, Action: "begin", Self: nodeA, PeerCapacity: 40, MessageCapacity: 1024})
	put(&journal.CacheRec{Instance: 1, Sequence: 1, Action: "gossip", Code: 0x13, Key: key, PayloadSHA256: sum, Cause: event.CauseRetry, Available: true, Candidates: []types.Address{peerB}, Targets: []types.Address{peerB}, Mono: 1, WallNs: 100})
	laterCause := event.CauseRelay
	if mode == "held-write" {
		laterCause = event.CauseRetry
	}
	seq := uint64(2)
	if mode == "missing-operation" {
		seq = 3
	}
	put(&journal.CacheRec{Instance: 1, Sequence: seq, Action: "gossip", Code: 0x13, Key: key, PayloadSHA256: sum, Cause: laterCause, Known: true, Available: true, Candidates: []types.Address{peerB}, Suppressed: []types.Address{peerB}, Mono: 1, WallNs: 100})
	if mode == "gap" {
		put(&journal.GapRec{Dropped: 1})
	}
	put(&journal.SuppressedRec{PeerIdx: 1, DedupKey: key, Cause: laterCause, Reason: "peer_recent_cache", Cache: 1, Operation: seq})
	frame := &journal.MsgRec{Dir: journal.Out, PeerIdx: 1, Code: 0x13, Payload: payload, DedupKey: key, Cause: event.CauseRetry, Write: "ok", Mono: 3, WallNs: 102, Attempt: &journal.SendAttempt{Sequence: 9, Cache: 1, Operation: 1}}
	switch mode {
	case "payload-change":
		frame.Payload = []byte{0xc1}
	case "held-write":
		frame.Cause = laterCause
		frame.Attempt.Operation = 2
	case "missing-reference":
		frame.Attempt.Operation = 77
	}
	put(frame)
	if mode == "duplicate-attempt" {
		put(frame)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExportCacheSourceRetainsDecisionAndPhysicalOrder(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprint(bounded), func(t *testing.T) {
			fs := fsys.NewMem()
			cacheFixture(t, fs, "")
			from, to := "", ""
			if bounded {
				from, to = "100", "110"
			}
			if _, err := exportR01(fs, "/cache", "/out", from, to); err != nil {
				t.Fatal(err)
			}
			rows := readFrames(t, fs, "/out/frames-cache-fixture.jsonl")
			counts := map[string]int{}
			var first, frame, suppressed map[string]any
			var frameAt, suppressedAt int
			for i, r := range rows {
				typ := r["type"].(string)
				counts[typ]++
				switch typ {
				case "cache_trace":
					trace := r["cache_trace"].(map[string]any)
					if trace["instances"] != "1" || trace["operations"] != "2" || trace["complete"] != true || r["clock_source"] != "unavailable" {
						t.Fatal("snapshot declaration lost", r)
					}
				case "cache_instance":
					if r["clock_source"] != "unavailable" {
						t.Fatal("declaration clock invented")
					}
				case "cache_operation":
					if r["cache_operation"].(map[string]any)["sequence"] == "1" {
						first = r
					}
				case "frame":
					frame = r
					frameAt = i
				case "send_suppressed":
					suppressed = r
					suppressedAt = i
				}
			}
			if counts["cache_trace"] != 1 || counts["cache_instance"] != 1 || counts["cache_operation"] != 2 {
				t.Fatal(counts)
			}
			if bounded {
				if frame != nil || suppressed != nil {
					t.Fatal("height filter changed")
				}
				return
			}
			if first == nil || frame == nil || suppressed == nil || suppressedAt >= frameAt {
				t.Fatal("physical order changed", counts)
			}
			attempt := frame["send_attempt"].(map[string]any)
			ref := attempt["cache_decision"].(map[string]any)
			if attempt["available"] != true || attempt["sequence"] != "9" || ref["operation"] != "1" || ref["source_available"] != true || ref["source_seq"] != fmt.Sprint(first["seq"]) || frame["journal_segment"] == nil || frame["journal_offset"] == nil {
				t.Fatal("attempt lost original decision", frame, first)
			}
			if suppressed["cache_decision"].(map[string]any)["operation"] != "2" || suppressed["clock_source"] != "unavailable" {
				t.Fatal("suppression source lost", suppressed)
			}
		})
	}
}

func TestExportCacheSourceKeepsActualSuppressedWrite(t *testing.T) {
	fs := fsys.NewMem()
	cacheFixture(t, fs, "held-write")
	if _, err := exportR01(fs, "/cache", "/out", "", ""); err != nil {
		t.Fatal(err)
	}
	for _, r := range readFrames(t, fs, "/out/frames-cache-fixture.jsonl") {
		if r["type"] == "frame" {
			ref := r["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
			if ref["operation"] != "2" || ref["source_available"] != true {
				t.Fatal("real contradictory write hidden", r)
			}
			return
		}
	}
	t.Fatal("actual suppressed write removed")
}

func TestExportCacheSourceRejectsForgeryAndMarksMissing(t *testing.T) {
	for _, mode := range []string{"payload-change", "duplicate-attempt", "no-capability", "gap", "missing-operation", "missing-reference"} {
		t.Run(mode, func(t *testing.T) {
			fs := fsys.NewMem()
			cacheFixture(t, fs, mode)
			_, err := exportR01(fs, "/cache", "/out", "", "")
			if mode == "payload-change" || mode == "duplicate-attempt" || mode == "no-capability" {
				if err == nil {
					t.Fatal("forged source accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range readFrames(t, fs, "/out/frames-cache-fixture.jsonl") {
				if r["type"] == "cache_trace" && mode != "missing-reference" && r["cache_trace"].(map[string]any)["complete"] != false {
					t.Fatal("incomplete source declared complete", r)
				}
				if r["type"] == "frame" {
					found = true
					ref := r["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
					if ref["source_available"] != false {
						t.Fatal("missing source became positive proof", r)
					}
				}
			}
			if !found {
				t.Fatal("physical frame removed")
			}
		})
	}
}

func TestCacheSourceRejectsChangingJournalBetweenPasses(t *testing.T) {
	mem := fsys.NewMem()
	j, err := journal.Open(journal.Options{FS: mem, Dir: "/changing", Synchronous: true}, journal.Identity{Self: nodeA, Run: "changing-cache", Core: journal.CoreOptions{CacheTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Put(journal.Record{Body: &journal.CacheRec{Instance: 1, Action: "begin", Self: nodeA, PeerCapacity: 40, MessageCapacity: 1024}})
	if err = j.Sync(); err != nil {
		t.Fatal(err)
	}
	fs := &changingJournalFS{FS: mem, mutate: func() {
		j.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peerB, Event: "attached"}})
		if err := j.Sync(); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err = exportR01(fs, "/changing", "/out", "", ""); err == nil || !strings.Contains(err.Error(), "journal changed") {
		t.Fatal("changing cache source accepted", err)
	}
}

func TestCacheAndSchedulerShareOneRawDeclarationSequence(t *testing.T) {
	fs := fsys.NewMem()
	cacheFixture(t, fs, "with-scheduler")
	if _, err := exportR01(fs, "/cache", "/out", "", ""); err != nil {
		t.Fatal(err)
	}
	rows := readFrames(t, fs, "/out/frames-cache-fixture.jsonl")
	seen := map[float64]bool{}
	shared := false
	for _, r := range rows {
		seq := r["seq"].(float64)
		if seen[seq] {
			t.Fatal("duplicate raw sequence in combined source", seq)
		}
		seen[seq] = true
		if r["type"] == "scheduler_trace" {
			shared = true
			if r["cache_trace"] == nil || r["scheduler_trace"] == nil {
				t.Fatal("shared capability declaration lost", r)
			}
		}
	}
	if !shared {
		t.Fatal("actual node capability pair was not exercised")
	}
}
