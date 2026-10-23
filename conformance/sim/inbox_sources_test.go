package sim

import (
	"context"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
)

func inboxSourceBounds() journal.InboxLimits {
	return journal.InboxLimits{Core: cacheSourceLimits().Core, Operations: 20000, Entries: 10000, Peers: 256, Frames: 10000, Bytes: 64 << 20}
}

func TestInboxSourcesNormalQueuesAndOfflineContradictions(t *testing.T) {
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
		check, err := journal.CheckInboxSources(records, inboxSourceBounds())
		if err != nil || check.Status != "consistent" || check.Appended == 0 || check.Dequeued != check.Appended || check.Checked != check.Dequeued || check.Taken == 0 || check.Dispatched != check.Taken || check.RetainedTaken != 0 || check.Clears != 1 || check.RetainedQueued != 0 || check.RetainedChecking != 0 || check.RetainedSlots != 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
			t.Fatal("normal inbox source reconstruction", n.i, check, err)
		}
		if n.i != 0 {
			continue
		}
		var firstCheck *journal.InboxRec
		for _, record := range records {
			if r, ok := record.Body.(*journal.InboxRec); ok && r.Action == "check" {
				firstCheck = r
				break
			}
		}
		if firstCheck == nil || firstCheck.Result != "insert" {
			t.Fatal("normal first checked slot missing")
		}
		for _, action := range []string{"append", "dequeue", "check", "take"} {
			var boundary *journal.InboxRec
			for _, record := range records {
				if r, ok := record.Body.(*journal.InboxRec); ok && r.Action == action {
					boundary = r
					break
				}
			}
			if boundary == nil {
				t.Fatal("finite observed boundary missing", action)
			}
			// Keep original raw frame sources and only the already reached core
			// publications. Future queue mutations and core inputs supply no proof
			// that a still-queued/checking/ready request has completed.
			finite := []journal.Record{}
			for _, record := range records {
				if r, ok := record.Body.(*journal.InboxRec); ok && r.Sequence > boundary.Sequence {
					continue
				}
				if r, ok := record.Body.(*journal.CoreStepRec); ok && r.Step > firstCheck.SnapshotStep {
					continue
				}
				finite = append(finite, record)
			}
			actual, err := journal.CheckInboxSources(finite, inboxSourceBounds())
			if err != nil || actual.Status != "consistent" || (action != "take" && actual.Taken != 0) || actual.Dispatched != 0 || action == "take" && actual.RetainedTaken != 1 || action == "append" && actual.RetainedQueued != 1 || action == "dequeue" && actual.RetainedChecking != 1 || action == "check" && actual.RetainedSlots != 1 {
				t.Fatal("finite boundary invented completion", action, actual, err)
			}
		}
		// Every contradiction changes copied metadata after all normal nodes stop.
		// Original frames, signatures, inputs and clocks never reach a live node.
		for _, mode := range []string{"snapshot_owner", "snapshot_phase", "snapshot_context", "capture", "payload", "worker_choice", "worker_cursor", "consensus_cursor", "holder", "take_step", "request", "bytes", "sequence", "missing", "version", "unavailable", "discard", "operations", "entries", "peers", "frames", "span", "gap"} {
			t.Run(mode, func(t *testing.T) {
				copied := slices.Clone(records)
				bounds := inboxSourceBounds()
				want := "inconsistent"
				if mode == "operations" {
					bounds.Operations = 1
					want = "unavailable"
				}
				if mode == "entries" {
					bounds.Entries = 1
					want = "unavailable"
				}
				if mode == "peers" {
					bounds.Peers = 1
					want = "unavailable"
				}
				if mode == "frames" {
					bounds.Frames = 1
					want = "unavailable"
				}
				if mode == "span" {
					bounds.Bytes = 1
					want = "unavailable"
				}
				changed := false
				for i, record := range copied {
					r, ok := record.Body.(*journal.InboxRec)
					if !ok {
						continue
					}
					c := *r
					switch mode {
					case "snapshot_owner":
						if c.Action != "check" {
							continue
						}
						c.SnapshotStep = ^uint64(0)
						want = "unavailable"
					case "snapshot_phase":
						if c.Action != "check" {
							continue
						}
						c.SnapshotPhase = "stopped"
					case "snapshot_context":
						if c.Action != "check" {
							continue
						}
						c.SnapshotContextHash[0] ^= 1
					case "capture":
						if c.Action != "append" {
							continue
						}
						c.Capture++
						c.Origin.CaptureID++
					case "payload":
						if c.Action != "append" || len(c.Payload) == 0 {
							continue
						}
						c.Payload = slices.Clone(c.Payload)
						c.Payload[0] ^= 1
					case "worker_choice":
						if c.Action != "dequeue" {
							continue
						}
						c.Choice = uint64(len(c.Candidates))
					case "worker_cursor":
						if c.Action != "dequeue" {
							continue
						}
						c.WorkerCursor++
					case "consensus_cursor":
						if c.Action != "take" {
							continue
						}
						c.ConsensusCursor++
					case "holder":
						if c.Action != "check" || c.Result != "insert" {
							continue
						}
						c.Holder[0] ^= 1
					case "take_step":
						if c.Action != "dispatch" {
							continue
						}
						c.Step = ^uint64(0)
						want = "unavailable"
					case "request":
						if c.Action != "dequeue" {
							continue
						}
						c.Request = ^uint64(0)
					case "bytes":
						if c.Action != "append" {
							continue
						}
						c.BytesAfter++
					case "sequence":
						c.Sequence++
						if c.Action == "append" {
							c.Request = c.Sequence
						}
						want = "unavailable"
					case "missing":
						copied = append(copied[:i:i], copied[i+1:]...)
						want = "unavailable"
						changed = true
					case "version":
						c.Version++
						want = "unavailable"
					case "discard":
						if c.Action != "dispatch" {
							continue
						}
						c.Action = "discard"
						c.Step = 0
						c.Unavailable = "dispatch_deduplicated"
						want = "unavailable"
					case "unavailable":
						c.Unavailable = "snapshot_unavailable"
						want = "unavailable"
					case "gap":
						copied = append(copied, journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindInbox), Count: 1}}}})
						want = "unavailable"
						changed = true
					default:
						changed = true
					}
					if !changed {
						copied[i].Body = &c
					}
					changed = true
					break
				}
				if !changed {
					t.Fatal("normal evidence missing for offline contradiction", mode)
				}
				actual, err := journal.CheckInboxSources(copied, bounds)
				if actual.Status != want || (want == "inconsistent") != (err != nil) {
					t.Fatal("contradiction not classified", mode, actual, err)
				}
			})
		}
		// Observer delivery order is independent of mutex order.
		reordered := slices.Clone(records)
		positions := []int{}
		for i, r := range reordered {
			if _, ok := r.Body.(*journal.InboxRec); ok {
				positions = append(positions, i)
			}
		}
		for i := 0; i < len(positions)/2; i++ {
			a, b := positions[i], positions[len(positions)-1-i]
			reordered[a].Body, reordered[b].Body = reordered[b].Body, reordered[a].Body
		}
		actual, err := journal.CheckInboxSources(reordered, inboxSourceBounds())
		if err != nil || actual.Status != "consistent" || actual.Taken != check.Taken {
			t.Fatal("delivery order replaced actual mutex order", actual, err)
		}
	}
}
