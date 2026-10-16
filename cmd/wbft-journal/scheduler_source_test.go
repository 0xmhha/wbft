package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func schedulerFixture(t *testing.T, fs fsys.FS, trace uint64) {
	t.Helper()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/scheduler", Synchronous: true}, journal.Identity{Self: nodeA, Run: "scheduler-fixture", Core: journal.CoreOptions{TimerTrace: trace}})
	if err != nil {
		t.Fatal(err)
	}
	view := types.View{Sequence: types.HeightFromUint64(10)}
	input := func(kind consensus.TimerKind, gen uint64, round uint64) []byte {
		tm := consensus.Timeout{Kind: kind, Gen: gen, View: view}
		tm.View.Round = types.RoundFromUint64(round)
		raw, err := inputlog.Encode(tm)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	round, retry, next := input(consensus.RoundTimer, 7, 0), input(consensus.RetryTimer, 3, 0), input(consensus.RoundTimer, 8, 1)
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	op := func(seq, step, output, armStep, armOutput uint64, source, action string, at, entry, deadline time.Duration, body []byte, kinds ...uint64) {
		armEngine := uint64(1)
		if len(body) == 0 {
			armEngine = 0
		}
		w.Put(journal.Record{Body: &journal.TimerRec{Sequence: seq, EngineRun: 1, Step: step, Output: output, ArmEngineRun: armEngine, ArmStep: armStep, ArmOutput: armOutput, Source: source, Action: action, Mono: at, WallNs: origin + int64(at), EntryMono: entry, Deadline: deadline, Input: body, Kinds: kinds}})
	}
	step := func(n uint64, entry, done time.Duration, kind, via string) {
		w.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: n, Entry: &journal.StepMoment{Mono: entry, WallNs: origin + int64(entry)}, Mono: done, WallNs: origin + int64(done), InputKind: kind, Via: via}})
	}
	op(1, 1, 1, 1, 1, "core", "arm", 0, 0, 4*time.Second, round)
	op(2, 1, 2, 1, 2, "core", "arm", 0, 0, 4*time.Second, retry)
	step(1, 0, 0, inputlog.KindStart, "internal")
	op(3, 1, 1, 1, 1, "core", "queued", 4*time.Second, 0, 4*time.Second, round)
	op(4, 1, 2, 1, 2, "core", "queued", 4*time.Second, 0, 4*time.Second, retry)
	op(5, 2, 1, 0, 0, "core", "cancel", 4100*time.Millisecond, 0, 0, nil, 0, 1, 2)
	op(6, 2, 2, 2, 2, "core", "arm", 4100*time.Millisecond, 3*time.Second, 11*time.Second, next)
	step(2, 3*time.Second, 4200*time.Millisecond, inputlog.KindMessage, "peer")
	op(7, 3, 0, 1, 1, "dequeue", "pop", 5*time.Second, 0, 4*time.Second, round)
	step(3, 5*time.Second, 5*time.Second, inputlog.KindTimeout, "timer")
	op(8, 4, 0, 1, 2, "dequeue", "pop", 6*time.Second, 0, 4*time.Second, retry)
	step(4, 6*time.Second, 6*time.Second, inputlog.KindTimeout, "timer")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExportMeasuredSchedulerSource(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "bounded"}[bounded], func(t *testing.T) {
			fs := fsys.NewMem()
			schedulerFixture(t, fs, journal.TimerTraceVersion)
			args := []string{"export", "--dir", "/scheduler", "--out", "/out", "--format", "r01"}
			if bounded {
				args = append(args, "--from", "100", "--to", "110")
			}
			runJSON(t, fs, 0, nil, args...)
			rows := readFrames(t, fs, "/out/frames-scheduler-fixture.jsonl")
			counts := map[string]int{}
			for _, r := range rows {
				counts[r["type"].(string)]++
			}
			if counts["scheduler_trace"] != 1 || counts["timer_operation"] != 8 || counts["scheduler_step"] != 4 {
				t.Fatal("measured scheduler source lost", counts)
			}
			if rows[0]["scheduler_trace"].(map[string]any)["operations"] != "8" {
				t.Fatal("trace count lost", rows[0])
			}
			for _, r := range rows {
				if r["journal_segment"] == nil || r["journal_offset"] == nil {
					t.Fatal("physical source lost", r)
				}
				if r["type"] == "timer_operation" {
					op := r["timer_operation"].(map[string]any)
					if op["sequence"] == "5" && op["action"] != "cancel" {
						t.Fatal(op)
					}
				}
			}
			if !bounded && os.Getenv("WBFT_TIMER_FIXTURE_DIR") != "" {
				dest := os.Getenv("WBFT_TIMER_FIXTURE_DIR")
				if err := os.MkdirAll(dest, 0700); err != nil {
					t.Fatal(err)
				}
				raw, err := fs.ReadFile("/out/frames-scheduler-fixture.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dest, "frames-scheduler-fixture.jsonl"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLegacySchedulerMetadataIsNotInvented(t *testing.T) {
	fs := fsys.NewMem()
	schedulerFixture(t, fs, 0)
	runJSON(t, fs, 0, nil, "export", "--dir", "/scheduler", "--out", "/out", "--format", "r01")
	rows := readFrames(t, fs, "/out/frames-scheduler-fixture.jsonl")
	raw, _ := json.Marshal(rows)
	if len(rows) != 0 {
		t.Fatal("legacy source became a measured trace", string(raw))
	}
}

func TestSchedulerSourceRejectsChangingJournal(t *testing.T) {
	mem := fsys.NewMem()
	j, err := journal.Open(journal.Options{FS: mem, Dir: "/j", Synchronous: true}, journal.Identity{Self: nodeA, Run: "changing-timers", Core: journal.CoreOptions{TimerTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Sync(); err != nil {
		t.Fatal(err)
	}
	fs := &changingJournalFS{FS: mem, mutate: func() {
		j.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart}})
		if e := j.Sync(); e != nil {
			t.Fatal(e)
		}
	}}
	_, err = exportR01(fs, "/j", "/out", "", "")
	if err == nil || !strings.Contains(err.Error(), "journal changed") {
		t.Fatal("changing timer source accepted", err)
	}
}

func TestSchedulerSourceRejectsInvalidTimeoutMetadata(t *testing.T) {
	for _, name := range []string{"unknown action", "unknown source", "missing timeout", "invalid timeout", "cancel timeout", "invalid kind"} {
		t.Run(name, func(t *testing.T) {
			b := &journal.TimerRec{Action: "cancel", Source: "core"}
			switch name {
			case "unknown action":
				b.Action = "unknown"
			case "unknown source":
				b.Source = "unknown"
			case "missing timeout":
				b.Action = "arm"
			case "invalid timeout":
				b.Action = "arm"
				b.Input = []byte{1, 2, 3}
			case "cancel timeout":
				b.Input = []byte{1}
			case "invalid kind":
				b.Kinds = []uint64{3}
			}
			if _, err := timerMetadata(b); err == nil {
				t.Fatal("invalid scheduler source accepted")
			}
		})
	}
}
