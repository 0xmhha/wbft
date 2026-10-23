package sim

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
)

func finalizeSourceBounds() journal.FinalizeLimits {
	return journal.FinalizeLimits{Queue: journal.AppQueueLimits{Core: cacheSourceLimits().Core, Operations: 20000, Entries: 10000, Bytes: 64 << 20}, Operations: 20000, Tasks: 10000, Bytes: 64 << 20}
}

func TestFinalizeSourcesNormalCallsAndOfflineMetadataContradictions(t *testing.T) {
	sc := writeQueueScenario(t, false)
	sc.Until.Height = 4
	for i := range sc.Nodes {
		sc.Nodes[i].AcceptedCache = cacheExperimentProfile()
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range s.nodes {
		n.stop()
	}
	if result := s.result(); len(result.Violations) > 0 {
		t.Fatal(result.Violations)
	}
	for _, n := range s.nodes {
		records, err := journal.ReadAll(n.fs, journalDir)
		if err != nil {
			t.Fatal(err)
		}
		check, err := journal.CheckFinalizeSources(records, finalizeSourceBounds())
		if err != nil || check.Status != "consistent" || check.Enqueued < 3 || check.Entered != check.Enqueued || check.Returned != check.Enqueued || check.Notified != check.Enqueued || check.RetainedQueued != 0 || check.RetainedActive != 0 || check.RetainedReturned != 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
			t.Fatal("normal commit/call/result sources", n.i, check, err)
		}
		if n.i != 0 {
			continue
		}
		for _, action := range []string{"enqueue", "enter", "return"} {
			for i, record := range records {
				r, ok := record.Body.(*journal.FinalizeRec)
				if !ok || r.Action != action {
					continue
				}
				end := i + 1
				if action == "enqueue" {
					// The core observer is published after output execution. Retain its
					// completed source before claiming this queued finite horizon.
					for j := i + 1; j < len(records); j++ {
						if source, ok := records[j].Body.(*journal.CoreStepRec); ok && source.EngineRun == r.EngineRun && source.Step == r.Step {
							end = j + 1
							break
						}
					}
				}
				finite, err := journal.CheckFinalizeSources(records[:end], finalizeSourceBounds())
				if err != nil || finite.Status != "consistent" || finite.Enqueued != 1 || action == "enqueue" && finite.RetainedQueued != 1 || action == "enter" && finite.RetainedActive != 1 || action == "return" && finite.RetainedReturned != 1 {
					t.Fatal("unfinished normal horizon was invented as completion", action, finite, err)
				}
				break
			}
		}
		ambiguous := slices.Clone(records)
		var task uint64
		for _, record := range records {
			if r, ok := record.Body.(*journal.FinalizeRec); ok && r.Action == "return" {
				task = r.Task
				break
			}
		}
		for i, record := range ambiguous {
			if r, ok := record.Body.(*journal.FinalizeRec); ok && r.Task == task && (r.Action == "return" || r.Action == "notify") {
				changed := *r
				changed.HasError = true
				ambiguous[i].Body = &changed
			}
		}
		ambiguousCheck, err := journal.CheckFinalizeSources(ambiguous, finalizeSourceBounds())
		if err != nil || ambiguousCheck.Status != "unavailable" || ambiguousCheck.Reason != "finalization_error_presence_unrepresentable" {
			t.Fatal("lossy error presence became nil success", ambiguousCheck, err)
		}
		// Every negative case edits copied metadata after the normal run stops.
		// No changed packet, signature, timer, input or fault reaches a runner.
		for _, mode := range []string{"owner", "arguments", "fifo", "return", "append", "queue_run", "error_presence", "sequence", "missing", "operations", "tasks", "bytes", "version", "unavailable"} {
			t.Run(mode, func(t *testing.T) {
				copied := slices.Clone(records)
				bounds := finalizeSourceBounds()
				want := "inconsistent"
				switch mode {
				case "operations":
					bounds.Operations = 1
					want = "unavailable"
				case "tasks":
					bounds.Tasks = 1
					want = "unavailable"
				case "bytes":
					bounds.Bytes = 1
					want = "unavailable"
				default:
					modified := false
					for i, record := range copied {
						r, ok := record.Body.(*journal.FinalizeRec)
						if !ok {
							continue
						}
						action := "enqueue"
						switch mode {
						case "owner", "arguments":
							action = "enter"
						case "fifo":
							action = "dequeue"
						case "return":
							action = "return"
						case "append", "queue_run", "error_presence":
							action = "notify"
						}
						if r.Action != action {
							continue
						}
						changed := *r
						switch mode {
						case "owner":
							changed.Output++
						case "arguments":
							changed.Arguments = slices.Clone(r.Arguments)
							changed.Arguments[0] ^= 1
						case "fifo":
							changed.Before++
							changed.After++
						case "return":
							changed.Action = "enter"
							changed.Arguments = []byte{1}
						case "append":
							changed.QueueRequest += 100000
							want = "unavailable"
						case "queue_run":
							changed.QueueRun = "unrelated"
							want = "unavailable"
						case "error_presence":
							changed.HasError = true
						case "sequence":
							changed.Sequence++
						case "missing":
							copied = append(copied[:i:i], copied[i+1:]...)
							want = "unavailable"
						case "version":
							changed.Version++
							want = "unavailable"
						case "unavailable":
							changed.Unavailable = "owner_unavailable"
							want = "unavailable"
						}
						if mode != "missing" {
							copied[i].Body = &changed
						}
						modified = true
						break
					}
					if !modified {
						t.Fatal("positive source missing for copied case")
					}
				}
				got, err := journal.CheckFinalizeSources(copied, bounds)
				if got.Status != want || (want == "inconsistent" && !errors.Is(err, journal.ErrFinalizeSource)) || (want == "unavailable" && err != nil) {
					t.Fatal("copied contradiction accepted", mode, got, err)
				}
			})
		}
		copied := slices.Clone(records)
		var positions []int
		for i, r := range copied {
			if _, ok := r.Body.(*journal.FinalizeRec); ok {
				positions = append(positions, i)
			}
		}
		for i, j := 0, len(positions)-1; i < j; i, j = i+1, j-1 {
			copied[positions[i]], copied[positions[j]] = copied[positions[j]], copied[positions[i]]
		}
		got, err := journal.CheckFinalizeSources(copied, finalizeSourceBounds())
		if err != nil || got != check {
			t.Fatal("observer delivery replaced measured queue sequence", got, err)
		}
	}
}
