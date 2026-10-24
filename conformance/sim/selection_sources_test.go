package sim

import (
	"context"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
)

func selectionSourceBounds() journal.SelectionLimits {
	core := cacheSourceLimits().Core
	return journal.SelectionLimits{Internal: internalSourceBounds(), App: journal.AppQueueLimits{Core: core, Operations: 20000, Entries: 10000, Bytes: 64 << 20}, Timer: journal.TimerSourceLimits{Core: core, Operations: 20000, Bindings: 20000, Bytes: 64 << 20}, Inbox: inboxSourceBounds(), Operations: 20000, Sources: 100000, Bytes: 64 << 20}
}
func TestInputSelectionsNormalConditionalProbesAndOfflineContradictions(t *testing.T) {
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
		check, err := journal.CheckInputSelections(records, selectionSourceBounds())
		if err != nil || check.Status != "consistent" || check.Selected == 0 || check.Empty == 0 || check.Selected != check.Dispatched || check.RetainedSelected != 0 || check.Attempts != check.Selected+check.Empty || check.ScheduleStatus != "unavailable" || check.PhysicalStatus != "unavailable" {
			t.Fatal("normal conditional selection", n.i, check, err)
		}
		t.Logf("normal node=%d attempts=%d selected=%d empty=%d random=%d", n.i, check.Attempts, check.Selected, check.Empty, check.RandomChoices)
		if n.i != 0 {
			continue
		}
		for _, mode := range []string{"priority", "unperformed", "probe_state", "probe_source", "probe_time", "source", "input", "random", "dispatch", "owner", "sequence", "duplicate", "missing", "version", "unavailable", "operations", "sources", "span", "gap"} {
			t.Run(mode, func(t *testing.T) {
				copied := slices.Clone(records)
				bounds := selectionSourceBounds()
				want := "inconsistent"
				switch mode {
				case "operations":
					bounds.Operations = 1
					want = "unavailable"
				case "sources":
					bounds.Sources = 1
					want = "unavailable"
				case "span":
					bounds.Bytes = 1
					want = "unavailable"
				}
				changed := false
				for i, record := range copied {
					r, ok := record.Body.(*journal.SelectionRec)
					if !ok {
						continue
					}
					c := *r
					switch mode {
					case "priority":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Lane = "app"
					case "unperformed":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Timer = journal.InputProbe{State: "empty"}
					case "probe_state":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Internal.State = "empty"
					case "probe_source":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Internal.Sequence++
					case "probe_time":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Internal.Mono = c.Mono + 1
					case "source":
						if c.Action != "select" || c.Lane == "none" {
							continue
						}
						c.Source = ^uint64(0)
						want = "unavailable"
					case "input":
						if c.Action != "select" || c.Lane == "none" {
							continue
						}
						c.Input = slices.Clone(c.Input)
						c.Input[0] ^= 1
					case "random":
						if c.Action != "select" || c.Lane != "internal" {
							continue
						}
						c.Random = 1
					case "dispatch":
						if c.Action != "dispatch" {
							continue
						}
						c.Selection = ^uint64(0)
					case "owner":
						if c.Action != "select" {
							continue
						}
						c.Step = ^uint64(0)
						want = "unavailable"
					case "sequence":
						c.Sequence++
						if c.Action == "select" {
							c.Selection = c.Sequence
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
						c.Unavailable = "next_height_source"
						want = "unavailable"
					case "gap":
						copied = append(copied, journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindSelection), Count: 1}}}})
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
				got, e := journal.CheckInputSelections(copied, bounds)
				if got.Status != want || (want == "inconsistent") != (e != nil) {
					t.Fatal("offline contradiction not classified", mode, got, e)
				}
			})
		}
		reordered := slices.Clone(records)
		positions := []int{}
		for i, r := range reordered {
			if _, ok := r.Body.(*journal.SelectionRec); ok {
				positions = append(positions, i)
			}
		}
		for i := 0; i < len(positions)/2; i++ {
			a, b := positions[i], positions[len(positions)-1-i]
			reordered[a].Body, reordered[b].Body = reordered[b].Body, reordered[a].Body
		}
		got, e := journal.CheckInputSelections(reordered, selectionSourceBounds())
		if e != nil || got != check {
			t.Fatal("callback order replaced original sequence", got, check, e)
		}
	}
}
