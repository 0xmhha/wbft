package sim

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestValidatorStartNormalFourNodeEpochAndOrdinaryReopen(t *testing.T) {
	for _, mode := range []string{"off", "on", "mixed", "all-known"} {
		t.Run(mode, func(t *testing.T) {
			sc := timingCompatibilityScenario(t, 7)
			sc.Epochs = []EpochChange{{Block: 4, Candidates: []int{0, 1, 2}}}
			for i := range sc.Nodes {
				if mode == "on" || mode == "mixed" && i%2 == 0 {
					sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
				}
				if mode == "all-known" {
					sc.Nodes[i].Options.Improvements = consensus.KnownImprovements()
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
				t.Fatal("normal lifecycle failed", res.Violations)
			}
			for _, head := range res.Heads {
				if head < sc.Until.Height {
					t.Fatal("normal epoch/lifecycle did not progress", res.Heads)
				}
			}
			for _, n := range s.nodes {
				if !n.spec.Options.Improvements.Has(consensus.DeferValidatorStart) {
					continue
				}
				cfg := runner.Config{Core: n.spec.Options, ReplayWAL: true, NextHeight: n.spec.NextHeight, ValidatorHistory: n.spec.ValidatorHistory}
				cfg.Core.Config, cfg.Core.Self = n.cfg, n.v.address
				if _, err := runner.InspectWALForConfig(n.fs, walDir, cfg); err != nil {
					t.Fatal("actual normal history cannot be reconstructed", err)
				}
				records, _, err := wal.ReadAll(n.fs, walDir)
				if err != nil {
					t.Fatal(err)
				}
				var used uint64
				for _, record := range records {
					used += uint64(len(record.Body)) + 10
				}
				if used > cfg.ValidatorHistory.Bytes-1024 || uint64(len(records)) > cfg.ValidatorHistory.Records-1 {
					t.Fatal("normal history spent its terminal reserve")
				}
				t.Logf("node=%x records=%d functional_frame_bytes=%d", n.v.address[:4], len(records), used)
			}
		})
	}
}

func TestValidatorStartSimulationHistoryOwnership(t *testing.T) {
	sc := timingCompatibilityScenario(t, 2)
	limits := &runner.ValidatorHistoryLimits{Bytes: 1 << 20, Records: 4096}
	sc.Nodes[0].Options.Improvements = sc.Nodes[0].Options.Improvements.With(consensus.DeferValidatorStart)
	sc.Nodes[0].ValidatorHistory = limits
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	limits.Records++
	if s.nodes[0].spec.ValidatorHistory.Records != 4096 {
		t.Fatal("caller changed owned simulation history")
	}
	sc.Nodes[0].ReplayWAL = false
	if _, err := newSimulation(sc); err == nil {
		t.Fatal("selected history accepted replay-off")
	}
}

func TestValidatorStartFreshJournalTraceUsesActualFiveGenerations(t *testing.T) {
	for _, all := range []bool{false, true} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Schedule = nil
		for i := range sc.Nodes {
			sc.Nodes[i].Options.Improvements = sc.Nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
			if all {
				sc.Nodes[i].Options.Improvements = consensus.KnownImprovements()
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
		if len(res.Violations) != 0 {
			t.Fatal(res.Violations)
		}
		blocks, err := NewChainSource(res.Chain)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range s.nodes {
			reader, err := journal.OpenReader(n.fs, journalDir)
			if err != nil {
				t.Fatal(err)
			}
			steps := 0
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(step stepdriver.StepResult) error {
				steps++
				if !step.Match {
					t.Fatalf("fresh selected trace changed at node %d step %d", n.i, step.Step)
				}
				return nil
			})
			if err != nil || steps == 0 {
				t.Fatal("fresh five-counter trace not supported", err, steps)
			}
		}
	}
}

func TestValidatorStartActualDeferredHistoryAndNormalLifecycle(t *testing.T) {
	keys := testValidators(t, 4)
	nodes := make([]NodeSpec, 4)
	for i := range nodes {
		nodes[i] = DefaultNode()
		nodes[i].Options.Improvements = nodes[i].Options.Improvements.With(consensus.DeferValidatorStart)
		nodes[i].NextHeight = &runner.NextHeightLimits{Entries: 24, Bytes: 2 << 20, PerPeer: 12, PerSource: 6}
		nodes[i].WALSegmentBytes = 2048
	}
	nodes[3].ImportDelay = []time.Duration{3 * time.Second}
	var links []Link
	for _, key := range keys[:3] {
		links = append(links, Link{From: addrOf(key), To: addrOf(keys[3]), Delay: []time.Duration{10 * time.Millisecond, 2 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}})
	}
	sc := Scenario{Name: "normal-validator-history-receive", Seed: 17, Validators: keys, Nodes: nodes, Links: links, DefaultLink: Link{Delay: []time.Duration{10 * time.Millisecond}},
		Until: Stop{Height: 8, Duration: time.Minute}}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := s.result()
	if len(res.Violations) != 0 || res.Crashes != 0 || res.Damaged != 0 {
		t.Fatal("normal selected receive lifecycle failed", res.Violations)
	}
	for _, head := range res.Heads {
		if head < sc.Until.Height {
			t.Fatal("normal selected lane stopped", res.Heads)
		}
	}
	admitted, released := 0, 0
	for _, n := range s.nodes {
		records, _, err := wal.ReadAll(n.fs, walDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.Format == 2 && record.Kind == 7 {
				admitted++
			}
			if record.Format == 2 && (record.Kind == 8 || record.Kind == 9) {
				released++
			}
		}
		cfg := runner.Config{Core: n.spec.Options, ReplayWAL: true, NextHeight: n.spec.NextHeight, ValidatorHistory: n.spec.ValidatorHistory}
		cfg.Core.Config, cfg.Core.Self = n.cfg, n.v.address
		if _, err := runner.InspectWALForConfig(n.fs, walDir, cfg); err != nil {
			t.Fatal("actual selected deferred prefix not replayable", err)
		}
	}
	if admitted == 0 || released == 0 {
		t.Fatal("normal timing did not exercise real selected deferred history", admitted, released)
	}
	// The earlier operator stop missed the positive receive window. Preserve
	// the ordinary delay workload first, then normally reopen the stopped
	// owned nodes on exactly those captured records; no records are requeued.
	for _, n := range s.nodes {
		n.start()
		if n.r == nil || n.r.Halted() != nil || !n.r.LastReplay().Replayed {
			t.Fatal("actual deferred history ordinary reopen failed")
		}
		n.stop()
		cfg := runner.Config{Core: n.spec.Options, ReplayWAL: true, NextHeight: n.spec.NextHeight, ValidatorHistory: n.spec.ValidatorHistory}
		cfg.Core.Config, cfg.Core.Self = n.cfg, n.v.address
		if _, err := runner.InspectWALForConfig(n.fs, walDir, cfg); err != nil {
			t.Fatal("reopened selected deferred prefix failed", err)
		}
	}
	t.Logf("actual selected deferred admissions=%d releases=%d", admitted, released)
}
