package sim

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
)

func serviceLifecycle(t *testing.T) (*simulation, *node) {
	t.Helper()
	sc := Scenario{Validators: testValidators(t, 4), Until: Stop{Duration: 5 * time.Second}, Nodes: []NodeSpec{DefaultNode(), DefaultNode(), DefaultNode(), DefaultNode()}}
	sc.Nodes[0].Processing = &ProcessingProfile{Workers: 1, Costs: []ProcessingCost{{Phase: runner.ProcessingCore, Kind: inputlog.KindPeerConnected, Samples: []time.Duration{500 * time.Millisecond}}}}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	for _, n := range s.nodes {
		n.start()
	}
	n := s.nodes[0]
	n.r.PeerConnected(s.nodes[1].v.address)
	n.pump()
	if !n.r.ProcessingPending() {
		t.Fatal("lifecycle test did not reserve core service")
	}
	return s, n
}

func TestProcessingFullStopAndRestartWaitForReservedInput(t *testing.T) {
	s, n := serviceLifecycle(t)
	old, incarnation := n.r, n.inc
	n.stop()
	n.start()
	if !n.stopRequested || !n.restartRequested || !n.alive || !n.down || n.r != old || n.inc != incarnation {
		t.Fatal("restart overtook old input and its logs")
	}
	s.l.runAt(500 * time.Millisecond)
	n.pump()
	if n.stopRequested || n.restartRequested || !n.alive || n.down || n.r == old || n.inc != incarnation+1 || old.Running() {
		t.Fatal("graceful input completion did not release restart")
	}
}

func TestProcessingEngineControlsKeepTheirOrderAndIncarnation(t *testing.T) {
	s, n := serviceLifecycle(t)
	old, incarnation, generation := n.r, n.inc, n.r.EngineRun()
	for _, a := range []string{ActionEngineStop, ActionEngineStart, ActionEngineStop} {
		n.requestEngineAction(a)
	}
	n.pump()
	if len(n.engineActions) != 3 || !old.Running() {
		t.Fatal("engine controls overtook core service")
	}
	s.l.runAt(500 * time.Millisecond)
	n.pump()
	if len(n.engineActions) != 0 || n.r != old || n.inc != incarnation || old.Running() || old.EngineRun() != generation+1 {
		t.Fatal("ordered engine controls changed node identity or final state")
	}
}

func TestProcessingCrashInvalidatesOldCompletion(t *testing.T) {
	s, n := serviceLifecycle(t)
	old, step := n.r, n.r.Snapshot()
	n.crash()
	n.start()
	if n.r == old || n.inc != 2 {
		t.Fatal("crash did not replace the incarnation")
	}
	s.l.runAt(500 * time.Millisecond)
	if !reflect.DeepEqual(old.Snapshot(), step) || !old.ProcessingPending() {
		t.Fatal("old work executed against crashed storage")
	}
}

func TestProcessingHorizonDoesNotCompleteWorkOutsideCapture(t *testing.T) {
	s, n := serviceLifecycle(t)
	s.l.runAt(4800 * time.Millisecond)
	n.crash()
	n.start()
	n.r.PeerConnected(s.nodes[1].v.address)
	n.pump()
	before := n.r.Snapshot()
	s.l.runAt(s.sc.Until.Duration)
	if !n.r.ProcessingPending() || !reflect.DeepEqual(before, n.r.Snapshot()) {
		t.Fatal("work beyond capture horizon was completed")
	}
}

func processingFixture(d time.Duration) *ProcessingProfile {
	return &ProcessingProfile{Workers: 2, Costs: []ProcessingCost{
		{Phase: runner.ProcessingCheck, Kind: inputlog.KindMessage, Code: uint64(codec.CodePreprepare), Samples: []time.Duration{d / 2}},
		{Phase: runner.ProcessingCore, Kind: inputlog.KindMessage, Code: uint64(codec.CodePreprepare), Samples: []time.Duration{d, d + d/2}},
		{Phase: runner.ProcessingCore, Kind: inputlog.KindRequest, Samples: []time.Duration{d}},
	}}
}

func TestProcessingZeroProfilePreservesExactOriginalExecution(t *testing.T) {
	sc := Scenario{Validators: testValidators(t, 4), Seed: 17, Until: Stop{Height: 5, Duration: 20 * time.Second}}
	original, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	sc.Nodes = []NodeSpec{DefaultNode(), DefaultNode(), DefaultNode(), DefaultNode()}
	for i := range sc.Nodes {
		sc.Nodes[i].Processing = processingFixture(0)
	}
	again, err := Run(context.Background(), sc, Output{})
	if err != nil || !reflect.DeepEqual(original, again) {
		t.Fatal("zero profile changed results, random draws or evidence bytes", err)
	}
}

func TestProcessingProfileIsSeededAndDoesNotMutateCaller(t *testing.T) {
	sc := Scenario{Validators: testValidators(t, 4), Seed: 17, Until: Stop{Height: 5, Duration: 20 * time.Second}, Nodes: []NodeSpec{DefaultNode(), DefaultNode(), DefaultNode(), DefaultNode()}}
	for i := range sc.Nodes {
		sc.Nodes[i].Processing = processingFixture(40 * time.Millisecond)
	}
	first, err := Run(context.Background(), sc, Output{})
	if err != nil || len(first.Violations) != 0 {
		t.Fatal(first, err)
	}
	again, err := Run(context.Background(), sc, Output{})
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("same seed changed service execution", err)
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	s.nodes[0].spec.Processing.Costs[0].Samples[0]++
	if sc.Nodes[0].Processing.Costs[0].Samples[0] != 20*time.Millisecond {
		t.Fatal("processing samples alias the caller")
	}
}

func TestProcessingProfileValidation(t *testing.T) {
	for _, mutate := range []func(*ProcessingProfile){
		func(p *ProcessingProfile) { p.Workers = 0 },
		func(p *ProcessingProfile) { p.Workers = 257 },
		func(p *ProcessingProfile) { p.Costs[0].Phase = "other" },
		func(p *ProcessingProfile) { p.Costs[0].Kind = inputlog.KindStart },
		func(p *ProcessingProfile) { p.Costs[0].Code = 0 },
		func(p *ProcessingProfile) { p.Costs[0].Samples = nil },
		func(p *ProcessingProfile) { p.Costs[0].Samples[0] = -1 },
		func(p *ProcessingProfile) { p.Costs[0].Samples[0] = 2 * time.Minute },
		func(p *ProcessingProfile) { p.Costs = append(p.Costs, p.Costs[0]) },
	} {
		p := processingFixture(time.Millisecond)
		mutate(p)
		if _, err := cloneProcessing(p, time.Minute); err == nil {
			t.Fatal("invalid processing declaration accepted", p)
		}
	}
}
