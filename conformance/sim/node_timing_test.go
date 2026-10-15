package sim

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestRecordedInitialStartAndApplicationTiming(t *testing.T) {
	keys := testValidators(t, 4)
	nodes := make([]NodeSpec, 4)
	for i := range nodes {
		nodes[i] = DefaultNode()
		nodes[i].BuildDelay = []time.Duration{time.Duration(i+1) * 7 * time.Millisecond}
		nodes[i].ImportDelay = []time.Duration{time.Duration(i+1) * 5 * time.Millisecond}
	}
	nodes[3].StartAfter = 3 * time.Second
	sc := Scenario{Validators: keys, Nodes: nodes, Until: Stop{Height: 8, Duration: time.Minute}}
	res, err := Run(context.Background(), sc, Output{})
	if err != nil || len(res.Violations) > 0 {
		t.Fatalf("run %v/%v", err, res.Violations)
	}
	address := addrOf(keys[3])
	startFound := false
	builds := map[string]int{}
	requests := map[string]struct{ at, wait int64 }{}
	for name, raw := range res.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var x struct {
				Kind event.Kind `json:"kind"`
				Node string     `json:"node"`
				Mono int64      `json:"t_mono_ns"`
				Wait int64      `json:"wait_ms"`
			}
			if json.Unmarshal([]byte(line), &x) != nil {
				t.Fatal("event decode")
			}
			if x.Kind == event.BuildRequest {
				requests[x.Node] = struct{ at, wait int64 }{x.Mono, x.Wait}
			}
			if x.Kind == event.ProposalSubmitted {
				if req, ok := requests[x.Node]; ok {
					for i, key := range keys {
						if x.Node == hexAddr(addrOf(key)) {
							elapsed := time.Duration(x.Mono - req.at - req.wait*int64(time.Millisecond))
							if elapsed < nodes[i].BuildDelay[0] || elapsed >= nodes[i].BuildDelay[0]+time.Millisecond {
								t.Fatalf("node %d build delay %s", i, elapsed)
							}
							builds[x.Node]++
						}
					}
					delete(requests, x.Node)
				}
			}
			if x.Kind == event.NodeStart && x.Node == hexAddr(address) {
				startFound = true
				if x.Mono != int64(3*time.Second) {
					t.Fatalf("first start %s at %d", name, x.Mono)
				}
			}
		}
	}
	if !startFound {
		t.Fatal("delayed node never started")
	}
	if len(builds) != 4 {
		t.Fatalf("per-node build models not exercised: %v", builds)
	}
	// Caller samples must remain unchanged across repeated runs.
	if nodes[3].BuildDelay[0] != 28*time.Millisecond {
		t.Fatal("caller samples mutated")
	}
}

func TestNodeTimingRejectsInvalidSamples(t *testing.T) {
	for _, spec := range []NodeSpec{{StartAfter: -1}, {StartAfter: time.Minute}, {BuildDelay: []time.Duration{-1}}, {ImportDelay: []time.Duration{2 * time.Minute}}} {
		_, err := Run(context.Background(), Scenario{Validators: testValidators(t, 4), Nodes: []NodeSpec{spec}, Until: Stop{Height: 2, Duration: time.Minute}}, Output{})
		if err == nil {
			t.Fatal("invalid node timing accepted")
		}
	}
}

func TestPerNodeImportDelaySchedulesActualHead(t *testing.T) {
	keys := testValidators(t, 4)
	sc := Scenario{Validators: keys, Until: Stop{Height: 2, Duration: time.Minute}}
	result, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	sc.Nodes = []NodeSpec{DefaultNode()}
	sc.Nodes[0].ImportDelay = []time.Duration{17 * time.Millisecond}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	n := s.nodes[0]
	n.start()
	defer n.stop()
	if err := n.app.FinalizeBlock(result.Chain[1], types.RoundFromUint64(0)); err != nil {
		t.Fatal(err)
	}
	s.l.runAt(16 * time.Millisecond)
	if n.head() != 0 {
		t.Fatal("node imported before its recorded delay")
	}
	s.l.runAt(17 * time.Millisecond)
	if n.head() != 1 {
		t.Fatalf("node import did not occur at deadline, head %d", n.head())
	}
}

func TestNodeScheduleCannotStartBeforeRecordedInitialTime(t *testing.T) {
	keys := testValidators(t, 4)
	spec := DefaultNode()
	spec.StartAfter = 3 * time.Second
	for _, action := range []string{ActionStop, ActionRestart, ActionEngineStop, ActionEngineStart, "unknown"} {
		at := time.Second
		if action == "unknown" {
			at = 4 * time.Second
		}
		_, err := Run(context.Background(), Scenario{Validators: keys, Nodes: []NodeSpec{spec}, Until: Stop{Height: 3, Duration: time.Minute}, Schedule: []NodeEvent{{Node: addrOf(keys[0]), At: at, Action: action}}}, Output{})
		if err == nil {
			t.Fatal("invalid lifecycle schedule accepted")
		}
	}
}

func TestRunWaitsForDelayedFirstIncarnations(t *testing.T) {
	nodes := make([]NodeSpec, 4)
	for i := range nodes {
		nodes[i] = DefaultNode()
		nodes[i].StartAfter = 3 * time.Second
	}
	result, err := Run(context.Background(), Scenario{Validators: testValidators(t, 4), Nodes: nodes, Until: Stop{Height: 2, Duration: time.Minute}}, Output{})
	if err != nil || len(result.Violations) > 0 {
		t.Fatalf("delayed run %v/%v", err, result.Violations)
	}
	if result.SimTime < 3*time.Second {
		t.Fatal("run completed before any node started")
	}
	for _, h := range result.Heads {
		if h < 2 {
			t.Fatal("delayed node did not reach target")
		}
	}
}
