package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/buildqueue"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/event/schema"
)

func serialSpec() NodeSpec {
	spec := DefaultNode()
	spec.BuildQueuePolicy = BuildQueueSerial
	spec.BuildDoneResult = BuildDoneFails
	spec.BuildDelay = []time.Duration{7 * time.Millisecond}
	return spec
}
func TestSerialBuildProfileKeepsOneAssemblyAndDeterministicEvidence(t *testing.T) {
	nodes := make([]NodeSpec, 4)
	for i := range nodes {
		nodes[i] = serialSpec()
	}
	sc := Scenario{Validators: testValidators(t, 4), Nodes: nodes, Until: Stop{Height: 8, Duration: time.Minute}}
	first, e := Run(context.Background(), sc, Output{})
	if e != nil || len(first.Violations) > 0 {
		t.Fatal(e, first.Violations)
	}
	modelSchema, e := schema.Load()
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, raw := range first.Events {
		started := map[string]bool{}
		active := 0
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if e = modelSchema.Validate([]byte(line)); e != nil {
				t.Fatal(e)
			}
			var r struct {
				Kind   event.Kind `json:"kind"`
				ID     string     `json:"build_id"`
				Status string     `json:"status"`
			}
			if e = json.Unmarshal([]byte(line), &r); e != nil {
				t.Fatal(e)
			}
			switch r.Kind {
			case event.BuildStarted:
				if started[r.ID] {
					t.Fatal("duplicate assembly")
				}
				started[r.ID] = true
				active++
				count++
				if active > 1 {
					t.Fatal("parallel assembly")
				}
			case event.BuildFinished:
				if started[r.ID] {
					delete(started, r.ID)
					active--
				}
			}
		}
	}
	if count < 8 {
		t.Fatal("serial application never built chain", count)
	}
	second, e := Run(context.Background(), sc, Output{})
	if e != nil || len(second.Chain) != len(first.Chain) {
		t.Fatal(e)
	}
	for i, b := range first.Chain {
		if codec.BlockHash(b.Header) != codec.BlockHash(second.Chain[i].Header) {
			t.Fatal("seed changed chain")
		}
	}
	for name, raw := range first.Events {
		if !bytes.Equal(raw, second.Events[name]) {
			t.Fatal("seed changed event trace", name)
		}
	}
}
func TestSerialStopRetainsAssemblyAndDefersRestart(t *testing.T) {
	for _, result := range []string{BuildDoneFails, BuildDoneSubmits} {
		t.Run(result, func(t *testing.T) {
			spec := serialSpec()
			spec.BuildDoneResult = result
			spec.BuildDelay = []time.Duration{10 * time.Second}
			s, e := newSimulation(Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{spec}, Until: Stop{Duration: time.Minute}})
			if e != nil {
				t.Fatal(e)
			}
			s.ctx = context.Background()
			n := s.nodes[0]
			n.start()
			defer n.stop()
			s.pumpAll()
			for n.app.serial.q.Phase() != buildqueue.Assembling {
				at, ok := s.l.nextTime()
				if !ok || at > 5*time.Second {
					t.Fatal("assembly absent")
				}
				s.l.runAt(at)
				s.pumpAll()
			}
			oldRun := n.runID()
			inc := n.inc
			id := n.app.serial.q.ActiveID()
			n.stop()
			if n.app.serial.q.ActiveID() != id {
				t.Fatal("stop invented executor completion")
			}
			n.start()
			if n.alive || n.inc != inc {
				t.Fatal("restart overlapped old worker")
			}
			deadline := s.l.c.Mono() + 10*time.Second
			s.l.c.AdvanceTo(deadline)
			s.pumpAll()
			if !n.alive || n.inc != inc+1 {
				t.Fatal("restart did not follow actual return")
			}
			found := false
			for _, line := range strings.Split(n.eventFiles["events-"+oldRun+".jsonl"].String(), "\n") {
				var r struct {
					Kind       event.Kind `json:"kind"`
					ID, Status string
				}
				var raw map[string]json.RawMessage
				if json.Unmarshal([]byte(line), &raw) != nil {
					continue
				}
				_ = json.Unmarshal(raw["kind"], &r.Kind)
				_ = json.Unmarshal(raw["build_id"], &r.ID)
				_ = json.Unmarshal(raw["status"], &r.Status)
				if r.Kind == event.BuildFinished && r.ID == id {
					found = true
					if r.Status != result {
						t.Fatal("wrong executor result", r.Status)
					}
				}
			}
			if !found {
				t.Fatal("completion moved to new run")
			}
		})
	}
}
func TestSerialBuildPolicyRequiresExplicitDoneBehavior(t *testing.T) {
	for _, spec := range []NodeSpec{{BuildQueuePolicy: "unknown"}, {BuildQueuePolicy: BuildQueueSerial}, {BuildDoneResult: BuildDoneFails}} {
		_, e := newSimulation(Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{spec}, Until: Stop{Duration: time.Minute}})
		if e == nil {
			t.Fatal("unknown policy became default")
		}
	}
}

func TestSerialCrashDoesNotInventExecutorCompletion(t *testing.T) {
	spec := serialSpec()
	spec.BuildDelay = []time.Duration{10 * time.Second}
	s, e := newSimulation(Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{spec}, Until: Stop{Duration: time.Minute}})
	if e != nil {
		t.Fatal(e)
	}
	s.ctx = context.Background()
	n := s.nodes[0]
	n.start()
	s.pumpAll()
	for n.app.serial.q.Phase() != buildqueue.Assembling {
		at, ok := s.l.nextTime()
		if !ok || at > 5*time.Second {
			t.Fatal("assembly absent")
		}
		s.l.runAt(at)
		s.pumpAll()
	}
	run := n.runID()
	id := n.app.serial.q.ActiveID()
	n.crash()
	s.l.c.AdvanceTo(s.l.c.Mono() + 11*time.Second)
	for _, line := range strings.Split(n.eventFiles["events-"+run+".jsonl"].String(), "\n") {
		var r struct {
			Kind event.Kind `json:"kind"`
			ID   string     `json:"build_id"`
		}
		_ = json.Unmarshal([]byte(line), &r)
		if r.ID == id && r.Kind == event.BuildFinished {
			t.Fatal("crash fabricated a return")
		}
	}
}

func TestSerialBuildProfileIsExplicitPerNode(t *testing.T) {
	keys := testValidators(t, 4)
	nodes := []NodeSpec{serialSpec(), DefaultNode(), DefaultNode(), DefaultNode()}
	result, e := Run(context.Background(), Scenario{Validators: keys, Nodes: nodes, Until: Stop{Height: 5, Duration: time.Minute}}, Output{})
	if e != nil || len(result.Violations) > 0 {
		t.Fatal(e, result.Violations)
	}
	profiles := 0
	for _, raw := range result.Events {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var r struct {
				Kind  event.Kind     `json:"kind"`
				Node  string         `json:"node"`
				Model map[string]any `json:"application_model"`
			}
			if e = json.Unmarshal([]byte(line), &r); e != nil {
				t.Fatal(e)
			}
			if r.Kind == event.NodeStart && r.Model != nil {
				profiles++
				if r.Node != hexAddr(addrOf(keys[0])) || r.Model["build_queue"] != BuildQueueSerial {
					t.Fatal("policy applied to unrelated node")
				}
			}
		}
	}
	if profiles != 1 {
		t.Fatal("policy declaration missing", profiles)
	}
}
