package sim

import (
	"context"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func internalSourceBounds() journal.InternalLimits {
	return journal.InternalLimits{Core: cacheSourceLimits().Core, Operations: 20000, Entries: 10000, Outputs: 10000, Bytes: 64 << 20}
}

func TestInternalSourcesNormalQueuesAndOfflineContradictions(t *testing.T) {
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
		check, err := journal.CheckInternalSources(records, internalSourceBounds())
		if err != nil || check.Status != "consistent" || check.Appended == 0 || check.OwnMessages == 0 || check.Popped != check.Appended || check.Dispatched != check.Popped || check.Resets != 1 || check.Clears != 1 || check.RetainedQueued != 0 || check.RetainedTaken != 0 || check.SignerStatus != "unavailable" || check.ScheduleStatus != "unavailable" || check.PhysicalStatus != "unavailable" {
			t.Fatal("normal internal source reconstruction", n.i, check, err)
		}
		t.Logf("normal node=%d appended=%d scheduled=%d own=%d dispatched=%d", n.i, check.Appended, check.Scheduled, check.OwnMessages, check.Dispatched)
		if n.i != 0 {
			continue
		}
		var first *journal.InternalRec
		var firstPop *journal.InternalRec
		for _, record := range records {
			if r, ok := record.Body.(*journal.InternalRec); ok {
				if r.Action == "append" && first == nil {
					first = r
				}
				if r.Action == "pop" && firstPop == nil {
					firstPop = r
				}
			}
		}
		if first == nil || firstPop == nil {
			t.Fatal("normal finite source missing")
		}
		// Future source records do not supply evidence that a selected input ran.
		for _, boundary := range []*journal.InternalRec{first, firstPop} {
			finite := []journal.Record{}
			for _, record := range records {
				if r, ok := record.Body.(*journal.CoreStepRec); ok && r.Step > first.Step {
					continue
				}
				if r, ok := record.Body.(*journal.InternalRec); ok && r.Sequence > boundary.Sequence {
					continue
				}
				finite = append(finite, record)
			}
			got, e := journal.CheckInternalSources(finite, internalSourceBounds())
			if e != nil || got.Status != "consistent" || got.Dispatched != 0 || boundary == first && got.RetainedQueued != 1 || boundary == firstPop && got.RetainedTaken != 1 {
				t.Fatal("finite queue/take invented execution", boundary.Action, got, e)
			}
		}

		// A single independently recomputed output cannot produce two appends,
		// even when their copied inputs and source owner are byte-identical.
		reused := []journal.Record{}
		for _, record := range records {
			if r, ok := record.Body.(*journal.CoreStepRec); ok && r.Step > first.Step {
				continue
			}
			if r, ok := record.Body.(*journal.InternalRec); ok && r.Sequence > first.Sequence {
				continue
			}
			reused = append(reused, record)
		}
		duplicate := *first
		duplicate.Sequence++
		duplicate.Request = duplicate.Sequence
		duplicate.Before, duplicate.After = 1, 2
		reused = append(reused, journal.Record{Body: &duplicate})
		gotReuse, eReuse := journal.CheckInternalSources(reused, internalSourceBounds())
		if eReuse == nil || gotReuse.Status != "inconsistent" || gotReuse.Reason != "internal_output_reused" {
			t.Fatal("reused output accepted", gotReuse, eReuse)
		}
		for _, mode := range []string{"output", "owner", "request", "input", "own_peer", "own_signature", "sequence", "duplicate", "missing", "version", "unavailable", "reset", "clear", "dispatch", "operations", "entries", "outputs", "span", "gap"} {
			t.Run(mode, func(t *testing.T) {
				copied := slices.Clone(records)
				bounds := internalSourceBounds()
				want := "inconsistent"
				switch mode {
				case "operations":
					bounds.Operations = 1
					want = "unavailable"
				case "entries":
					bounds.Entries = 1
					want = "unavailable"
				case "outputs":
					bounds.Outputs = 1
					want = "unavailable"
				case "span":
					bounds.Bytes = 1
					want = "unavailable"
				}
				changed := false
				for i, record := range copied {
					r, ok := record.Body.(*journal.InternalRec)
					if !ok {
						continue
					}
					c := *r
					switch mode {
					case "output":
						if c.Action != "append" {
							continue
						}
						c.Output = ^uint64(0)
						want = "unavailable"
					case "owner":
						if c.Action != "append" {
							continue
						}
						c.Step = ^uint64(0)
						want = "unavailable"
					case "request":
						if c.Action != "pop" {
							continue
						}
						c.Request = ^uint64(0)
					case "input":
						if c.Action != "pop" {
							continue
						}
						c.Input = slices.Clone(c.Input)
						c.Input[0] ^= 1
					case "own_peer", "own_signature":
						if c.Action != "append" || c.Origin != "own" {
							continue
						}
						decoded, e := inputlog.Decode(c.InputKind, c.Input, nil)
						if e != nil {
							t.Fatal(e)
						}
						m := decoded.(consensus.Message)
						if mode == "own_peer" {
							m.Peer[0] ^= 1
						} else {
							m.Payload = slices.Clone(m.Payload)
							m.Payload[len(m.Payload)-1] ^= 1
						}
						c.Input, e = inputlog.Encode(m)
						if e != nil {
							t.Fatal(e)
						}
					case "sequence":
						c.Sequence++
						if c.Action == "append" {
							c.Request = c.Sequence
						}
						want = "unavailable"
					case "duplicate":
						copied = append(copied, record)
						changed = true
					case "missing":
						copied = append(copied[:i:i], copied[i+1:]...)
						want = "unavailable"
						changed = true
					case "version":
						c.Version++
						want = "unavailable"
					case "unavailable":
						c.Unavailable = "signer_state"
						want = "unavailable"
					case "reset":
						if c.Action != "reset" {
							continue
						}
						c.EngineRun++
						want = "unavailable"
					case "clear":
						if c.Action != "clear" {
							continue
						}
						c.Step--
						want = "inconsistent"
					case "dispatch":
						if c.Action != "dispatch" {
							continue
						}
						c.Request = ^uint64(0)
					case "gap":
						copied = append(copied, journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindInternal), Count: 1}}}})
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
					t.Fatal("normal evidence missing", mode)
				}
				got, e := journal.CheckInternalSources(copied, bounds)
				if got.Status != want || (want == "inconsistent") != (e != nil) {
					t.Fatal("offline contradiction not classified", mode, got, e)
				}
			})
		}
		// Reordered observer delivery preserves the original loop sequence.
		reordered := slices.Clone(records)
		positions := []int{}
		for i, r := range reordered {
			if _, ok := r.Body.(*journal.InternalRec); ok {
				positions = append(positions, i)
			}
		}
		for i := 0; i < len(positions)/2; i++ {
			a, b := positions[i], positions[len(positions)-1-i]
			reordered[a].Body, reordered[b].Body = reordered[b].Body, reordered[a].Body
		}
		got, e := journal.CheckInternalSources(reordered, internalSourceBounds())
		if e != nil || got != check {
			t.Fatal("delivery order replaced source sequence", got, check, e)
		}
	}
}
