package sim

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// The only scheduled events are ordinary stop and restart. No packet rewrite,
// network fault, signed-history mutation or adversarial actor is introduced.
func TestRoundChangeDomainNormalEpochAndOrdinaryReopen(t *testing.T) {
	for _, mode := range []string{"legacy", "domain", "domain-defer", "domain-mixed"} {
		t.Run(mode, func(t *testing.T) {
			sc := timingCompatibilityScenario(t, 7)
			sc.Epochs = []EpochChange{{Block: 4, Candidates: []int{0, 1, 2}}}
			if mode != "legacy" {
				sc.Params.RuleActivations = map[types.RuleName]string{types.RoundChangeDomainRule: "3"}
			}
			for i := range sc.Nodes {
				if mode == "domain-defer" || mode == "domain-mixed" && i%2 == 0 {
					sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
				}
			}
			s, err := newSimulation(sc)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			res := s.result()
			if len(res.Violations) != 0 || res.Crashes != 0 || res.Damaged != 0 {
				t.Fatal("normal domain lifecycle failed", res.Violations)
			}
			for _, head := range res.Heads {
				if head < sc.Until.Height {
					t.Fatal("normal epoch did not progress", res.Heads)
				}
			}
			for _, n := range s.nodes {
				if mode == "legacy" {
					if n.spec.Options.RoundChangeDomain != nil {
						t.Fatal("legacy scenario acquired a domain")
					}
					continue
				}
				cfg := runner.Config{Core: n.spec.Options, ReplayWAL: true, NextHeight: n.spec.NextHeight, ValidatorHistory: n.spec.ValidatorHistory}
				cfg.Core.Config, cfg.Core.Self = n.cfg, n.v.address
				if _, err := runner.InspectWALForConfig(n.fs, walDir, cfg); err != nil {
					t.Fatal("actual normal domain history cannot be reconstructed", err)
				}
				records, _, err := wal.ReadAll(n.fs, walDir)
				if err != nil || len(records) == 0 || records[0].Format != 6 {
					t.Fatal("actual domain run omitted its functional profile", err)
				}
				raw, err := n.fs.ReadFile(privvalDir + "/state")
				if err != nil || len(raw) == 0 || raw[0] != 2 {
					t.Fatal("normal signer did not retain format 2", err)
				}
				observed, err := journal.ReadAll(n.fs, journalDir)
				if err != nil {
					t.Fatal(err)
				}
				segments := 0
				for _, record := range observed {
					if segment, ok := record.Body.(*journal.SegmentRec); ok {
						segments++
						if len(segment.Core.DomainBytes) == 0 || segment.ValidateDomainIdentity() != nil {
							t.Fatal("actual sim segment lost its bound domain")
						}
					}
				}
				if segments == 0 {
					t.Fatal("normal simulator omitted its source segment")
				}
				t.Logf("node=%d records=%d", n.i, len(records))
			}
		})
	}
}

func TestRoundChangeDomainNormalFunctionalTrace(t *testing.T) {
	for _, deferStart := range []bool{false, true} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Schedule = nil
		sc.Params.RuleActivations = map[types.RuleName]string{types.RoundChangeDomainRule: "3"}
		if deferStart {
			for i := range sc.Nodes {
				sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
			}
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
		result := s.result()
		if len(result.Violations) != 0 {
			t.Fatal(result.Violations)
		}
		blocks, err := NewChainSource(result.Chain)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range s.nodes {
			reader, err := journal.OpenReader(n.fs, journalDir)
			if err != nil {
				t.Fatal(err)
			}
			steps := 0
			if err := stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(step stepdriver.StepResult) error {
				steps++
				if !step.Match {
					t.Fatal("normal selected functional trace differs", n.i, step.Step)
				}
				return nil
			}); err != nil || steps == 0 {
				t.Fatal("selected functional trace not reconstructed", n.i, steps, err)
			}
			answers, err := journal.OpenReader(n.fs, journalDir)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := stepdriver.NewAnswerPool(answers)
			if err != nil {
				t.Fatal(err)
			}
			reader, err = journal.OpenReader(n.fs, journalDir)
			if err != nil {
				t.Fatal(err)
			}
			steps = 0
			if err := stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: blocks, Answers: pool}, func(step stepdriver.TimedResult) error {
				steps++
				if !step.Result.Match {
					t.Fatal("normal selected timed baseline differs", n.i, step.Result.Step)
				}
				return nil
			}); err != nil || steps == 0 {
				t.Fatal("selected timed baseline not reconstructed", n.i, steps, err)
			}
		}
	}
}

func TestRoundChangeDomainNormalCacheSourceChain(t *testing.T) {
	for _, activation := range []string{"", "3", "100"} {
		t.Run("activation-"+activation, func(t *testing.T) {
			sc := writeQueueScenario(t, false)
			sc.Until.Height = 4
			if activation != "" {
				sc.Params.RuleActivations = map[types.RuleName]string{types.RoundChangeDomainRule: activation}
			}
			for i := range sc.Nodes {
				sc.Nodes[i].AcceptedCache = cacheExperimentProfile()
				if activation != "" && i%2 == 0 {
					sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
				}
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
			if res := s.result(); len(res.Violations) != 0 || res.Crashes != 0 || res.Damaged != 0 {
				t.Fatal("normal cache source run failed", res.Violations)
			}
			for _, n := range s.nodes {
				records, err := journal.ReadAll(n.fs, journalDir)
				if err != nil {
					t.Fatal(err)
				}
				core, err := journal.CheckCoreStepSources(records, cacheSourceLimits().Core)
				if err != nil || core.Status != "consistent" || core.Steps == 0 {
					t.Fatal("core domain source was not reconstructed", n.i, core, err)
				}
				inbox, err := journal.CheckInboxSources(records, inboxSourceBounds())
				if err != nil || inbox.Status != "consistent" {
					t.Fatal("inbox domain source was not reconstructed", n.i, inbox, err)
				}
				internal, err := journal.CheckInternalSources(records, internalSourceBounds())
				if err != nil || internal.Status != "consistent" || internal.OwnMessages == 0 {
					t.Fatal("internal domain source was not reconstructed", n.i, internal, err)
				}
				selection, err := journal.CheckInputSelections(records, selectionSourceBounds())
				if err != nil || selection.Status != "consistent" {
					t.Fatal("selection did not retain domain-dependent proof", n.i, selection, err)
				}
				receive, err := journal.CheckReceiveDispatchSources(records, journal.ReceiveDispatchLimits{Receive: cacheSourceLimits(), Selections: selectionSourceBounds(), Operations: 20000, Bytes: 64 << 20})
				if err != nil || receive.Status != "consistent" {
					t.Fatal("receive dispatch did not retain domain-dependent proof", n.i, receive, err)
				}
				if n.head() < sc.Until.Height {
					t.Fatal("normal source run did not progress", n.i, n.head())
				}
			}
		})
	}
}
