package sim

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func cacheExperimentProfile() *AcceptedCacheProfile {
	return &AcceptedCacheProfile{Journal: CacheDiagnosticOnly, Limits: transport.CachePolicyLimits{
		ReceivePending: 256, ReceivePerPeer: 64, WritePending: 256, WritePerPeer: 64}}
}

func cacheSourceLimits() journal.ReceiveSourceLimits {
	return journal.ReceiveSourceLimits{
		Core:    journal.CoreSourceLimits{Records: 200000, Runs: 8, Steps: 10000, Environments: 10000, Outputs: 100000, Bytes: 256 << 20},
		Receive: journal.ReceiveCacheCheckLimits{Records: 200000, Ledgers: 8, Reordered: 64}, Frames: 10000, Captures: 10000, Sessions: 256}
}

func TestAcceptedCacheDiagnosticNormalSourceChain(t *testing.T) {
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
	result := s.result()
	if len(result.Violations) != 0 {
		t.Fatal(result.Violations)
	}
	var external, writes, recent uint64
	timers := 0
	for _, n := range s.nodes {
		if n.head() < 4 || n.r != nil {
			t.Fatal("normal diagnostic run did not stop at its accepted head")
		}
		records, err := journal.ReadAll(n.fs, journalDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			switch r := record.Body.(type) {
			case *journal.SegmentRec:
				if r.Mode != "diagnostic" || r.Core.TimerTrace != journal.TimerTraceVersion || r.Core.CachePolicy == nil || !errors.Is(r.Core.ValidateRuntimeProfiles(), journal.ErrCachePolicyReplay) {
					t.Fatal("diagnostic sources enabled unsupported functional replay")
				}
			case *journal.StepRec:
				t.Fatal("functional step journal was enabled in the cache experiment")
			case *journal.MsgRec:
				if r.IO != nil {
					t.Fatal("simulated service fabricated measured socket I/O")
				}
			case *journal.TimerRec:
				timers++
			}
		}
		limits := cacheSourceLimits()
		reads, err := journal.CheckReceiveSources(records, limits)
		if err != nil || reads.Status != "consistent" || reads.PhysicalStatus != "unavailable" || reads.ScheduleStatus != "unavailable" {
			t.Fatal("simulated original read/core ACCEPT/source connection", n.i, reads, err)
		}
		writeCheck, err := journal.CheckWriteIOSources(records, journal.WriteIOCheckLimits{Records: 200000, Ledgers: 8, Reordered: 64, Sessions: 256, Requests: 10000, Frames: 10000})
		if err != nil || writeCheck.Status != "consistent" || writeCheck.PhysicalStatus != "unavailable" || writeCheck.Writes == 0 || writeCheck.Unmeasured != writeCheck.Writes {
			t.Fatal("simulated original write source", n.i, writeCheck, err)
		}
		accepted, err := journal.CheckWriteAcceptedSources(records, journal.WriteAcceptedSourceLimits{Write: journal.WriteCacheCheckLimits{Records: 200000, Ledgers: 8, Reordered: 64}, Receive: limits})
		if err != nil || accepted.Status != "consistent" || accepted.PhysicalStatus != "unavailable" || accepted.ScheduleStatus != "unavailable" {
			t.Fatal("simulated accepted-input recent source", n.i, accepted, err)
		}
		timerLimits := journal.TimerSourceLimits{Core: limits.Core, Operations: 20000, Bindings: 20000, Bytes: 64 << 20}
		timerCheck, err := journal.CheckTimerSources(records, timerLimits)
		if err != nil || timerCheck.Status != "consistent" || timerCheck.Arms == 0 || timerCheck.Cancels == 0 || timerCheck.PhysicalStatus != "unavailable" || timerCheck.ScheduleStatus != "unavailable" {
			t.Fatal("simulated core/scheduler source bindings", n.i, timerCheck, err)
		}
		if n.i == 0 {
			// Only copied offline source metadata changes. No altered timer,
			// packet, signature or fault command reaches the running model.
			for _, mode := range []string{"missing_arm", "changed_deadline", "inspection_limit"} {
				copied := slices.Clone(records)
				bounds := timerLimits
				if mode == "inspection_limit" {
					bounds.Operations = 1
				} else {
					for index, record := range copied {
						if timer, ok := record.Body.(*journal.TimerRec); ok && timer.Action == "arm" && timer.Source == "core" {
							if mode == "missing_arm" {
								copied = append(copied[:index:index], copied[index+1:]...)
							} else {
								value := *timer
								value.Deadline++
								copied[index].Body = &value
							}
							break
						}
					}
				}
				check, err := journal.CheckTimerSources(copied, bounds)
				if mode == "changed_deadline" {
					if check.Status != "inconsistent" || !errors.Is(err, journal.ErrTimerSource) {
						t.Fatal("offline timer contradiction accepted", mode, check, err)
					}
				} else if err != nil || check.Status != "unavailable" {
					t.Fatal("missing or bounded timer source became proof", mode, check, err)
				}
			}
		}
		external += reads.External
		writes += writeCheck.Writes
		recent += accepted.Registrations
	}
	if external == 0 || writes == 0 || recent == 0 || timers == 0 {
		t.Fatal("empty source comparison", external, writes, recent, timers)
	}
	t.Log("normal source comparisons; physical/schedule unavailable", "external", external, "writes", writes, "accepted recent", recent, "timers", timers)
}

func TestAcceptedCacheNormalMixedAndRestart(t *testing.T) {
	var baseline []types.Hash
	for _, mode := range []string{"off", "mixed", "all"} {
		sc := writeQueueScenario(t, false)
		for i := range sc.Nodes {
			if mode == "all" || mode == "mixed" && i%2 == 0 {
				sc.Nodes[i].AcceptedCache = cacheExperimentProfile()
			}
		}
		addr := addrOf(sc.Validators[3])
		sc.Schedule = []NodeEvent{{At: 2 * time.Second, Node: addr, Action: ActionStop}, {At: 4 * time.Second, Node: addr, Action: ActionRestart}}
		result, err := Run(context.Background(), sc, Output{})
		if err != nil || len(result.Violations) != 0 || result.Crashes != 0 {
			t.Fatal("normal cache experiment", mode, err, result)
		}
		for _, h := range result.Heads {
			if h < 8 {
				t.Fatal("normal restart did not reach canonical height", mode, result.Heads)
			}
		}
		var hashes []types.Hash
		for _, block := range result.Chain {
			hashes = append(hashes, codec.BlockHash(block.Header))
		}
		if baseline == nil {
			baseline = hashes
		} else {
			if len(hashes) != len(baseline) {
				t.Fatal("normal cache mode changed canonical chain length", mode)
			}
			for i, hash := range hashes {
				if hash != baseline[i] {
					t.Fatal("normal cache mode changed canonical block", mode, i)
				}
			}
		}
	}
}

func TestAcceptedCacheRequiresExplicitDiagnosticScope(t *testing.T) {
	sc := writeQueueScenario(t, false)
	p := cacheExperimentProfile()
	p.Journal = ""
	if _, err := cloneAcceptedCache(p, sc); err == nil {
		t.Fatal("implicit functional journal scope accepted")
	}
	p = cacheExperimentProfile()
	sc.Nodes[2].WriteQueue = nil
	if _, err := cloneAcceptedCache(p, sc); err == nil {
		t.Fatal("missing original endpoint capability replaced by a current address")
	}
}

func TestAcceptedCacheNormalBuildServiceTimeoutSources(t *testing.T) {
	sc := writeQueueScenario(t, false)
	sc.Until.Height = 3
	// Ordinary successful application service outlasts the initial timeout.
	// No frame, fault, partition or adversary is introduced.
	sc.App.BuildDelay = []time.Duration{3 * time.Second}
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
	result := s.result()
	if len(result.Violations) != 0 {
		t.Fatal("normal successful build service", result.Violations)
	}
	var pops uint64
	for _, n := range s.nodes {
		if n.head() < 3 {
			t.Fatal("normal service did not make progress", result.Heads)
		}
		records, err := journal.ReadAll(n.fs, journalDir)
		if err != nil {
			t.Fatal(err)
		}
		limits := journal.TimerSourceLimits{Core: cacheSourceLimits().Core, Operations: 20000, Bindings: 20000, Bytes: 64 << 20}
		check, err := journal.CheckTimerSources(records, limits)
		if err != nil || check.Status != "consistent" || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
			t.Fatal("actual normal timeout/core input binding", n.i, check, err)
		}
		pops += check.Timeouts
		// A copied source that points a timeout dequeue at an observed
		// non-timeout core input is a contradiction, not a new live input.
		if n.i == 0 {
			copied := slices.Clone(records)
			for index, record := range copied {
				if timer, ok := record.Body.(*journal.TimerRec); ok && timer.Action == "pop" && timer.Source == "dequeue" {
					value := *timer
					value.Step = 1 // this engine's observed Start input
					copied[index].Body = &value
					break
				}
			}
			changed, err := journal.CheckTimerSources(copied, limits)
			if changed.Status != "inconsistent" || !errors.Is(err, journal.ErrTimerSource) {
				t.Fatal("copied timeout source borrowed another input", changed, err)
			}
		}
	}
	if pops == 0 {
		t.Fatal("normal timeout source path not exercised")
	}
	t.Log("ordinary successful build service timeout bindings", pops, "physical/schedule unavailable")
}
