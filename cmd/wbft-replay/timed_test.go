package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/keccak"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/stepdriver"
)

func TestTimedReplayProtocolAndCLIKeepExactCoordinatesAndAssumptions(t *testing.T) {
	dir, chain := exportTimed(t)
	capSeconds := uint64(0)
	policy := &stepdriver.TimerPolicy{MaxRequestTimeoutSeconds: &capSeconds}
	var output bytes.Buffer
	if code := replayTimedOnce(dir, chain, policy, &output); code != 3 {
		t.Fatal("experiment became reproduction", code, output.String())
	}
	var input bytes.Buffer
	fmt.Fprintf(&input, "{\"type\":\"hello\",\"protocol\":%q}\n", Protocol)
	request := map[string]any{"type": "timed_replay", "id": 7, "journal": dir, "chain": chain, "answer_scope": "context", "timer_policy": policy}
	if err := json.NewEncoder(&input).Encode(request); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := serve(&input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	steps, done, capability := 0, false, false
	for decoder.More() {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		switch record["type"] {
		case "hello":
			for _, f := range record["features"].([]any) {
				if f == "timed_inputs_v1" {
					capability = true
				}
			}
		case "timed_step":
			steps++
			state, ok := record["execution_state"].(map[string]any)
			if !ok {
				t.Fatal("execution state missing", record)
			}
			if state["running"] == true {
				if _, ok := state["height"].(string); !ok {
					t.Fatal("execution height rounded", state)
				}
				if _, ok := state["round"].(string); !ok {
					t.Fatal("execution round rounded", state)
				}
			} else if state["height"] != nil || state["round"] != nil {
				t.Fatal("stopped core acquired a view", state)
			}
			if record["counterfactual"] != true || record["execution_model"] != stepdriver.TimedExperimentModel {
				t.Fatal("model lost", record)
			}
			if _, ok := record["execution_step"].(string); !ok {
				t.Fatal("execution coordinate rounded", record)
			}
			if record["generated"] == false {
				source := record["source_input"].(map[string]any)
				if _, ok := source["ordinal"].(string); !ok {
					t.Fatal("source coordinate rounded", record)
				}
			}
		case "timed_done":
			if record["counterfactual"] != true || record["horizon"] != "recorded_source_end" || record["future_tail_generated"] != false || record["timer_trace_validated"] != true {
				t.Fatal("completion scope lost", record)
			}
			done = true
		default:
			t.Fatal("unexpected reply", record)
		}
	}
	if steps == 0 || !done || !capability {
		t.Fatal(steps, done, capability)
	}
	source := timedSource(&stepdriver.TimedSource{Writer: "synthetic", Engine: 9007199254740993, Step: 9007199254740994, Ordinal: 9007199254740995}).(map[string]string)
	if source["engine_run"] != "9007199254740993" || source["ordinal"] != "9007199254740995" {
		t.Fatal(source)
	}
}
func TestTimedReplayRefusesIncompatiblePlansBeforeReadingSource(t *testing.T) {
	seconds := uint64(1)
	original := request{TimerPolicy: &stepdriver.TimerPolicy{RequestTimeoutSeconds: &seconds}, AnswerScope: "context", Journal: "/nonexistent", Chain: "/nonexistent"}
	for _, variant := range []string{"missing_policy", "step_answers", "warmup", "partial", "omit", "vars", "schedule"} {
		req := original
		switch variant {
		case "missing_policy":
			req.TimerPolicy = nil
		case "step_answers":
			req.AnswerScope = "step"
		case "warmup":
			req.WarmupFrom = 1
		case "partial":
			req.FromStep = 1
		case "omit":
			req.OmitMissing = true
		case "vars":
			req.WithVars = true
		case "schedule":
			req.Schedule = &stepdriver.TraceSchedule{Action: "drop"}
		}
		var reply map[string]any
		if err := timedRequest(req, func(v any) error { reply = v.(map[string]any); return nil }); err != nil {
			t.Fatal(err)
		}
		if reply["code"] != "timer_policy" {
			t.Fatal("incompatible plan reached source", variant, reply)
		}
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"request_timeout_seconds":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := loadTimerPolicy(path); err != nil || *p.RequestTimeoutSeconds != 1 {
		t.Fatal(p, err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", 4097)+`{"request_timeout_seconds":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTimerPolicy(path); err == nil {
		t.Fatal("oversized policy accepted")
	}
	var out bytes.Buffer
	if code := replayTimedOnce("/nonexistent", "/nonexistent", original.TimerPolicy, &out); code != 2 || strings.Contains(out.String(), "timed_done") {
		t.Fatal(code, out.String())
	}
}

func exportTimed(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	var validators []sim.Validator
	for i := 0; i < 4; i++ {
		v, err := sim.NewValidator(keccak.Sum256Bytes([]byte(fmt.Sprintf("timed-cli-%d", i))))
		if err != nil {
			t.Fatal(err)
		}
		validators = append(validators, v)
	}
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "timed-cli", Seed: 19, Validators: validators, Until: sim.Stop{Height: 2, Duration: time.Minute}}, sim.Output{JournalDir: dir})
	if err != nil || len(result.Journals) != 4 {
		t.Fatal(err, result.Violations, len(result.Journals))
	}
	nodes, _, err := sim.ReadJournalDir(dir)
	if err != nil || len(nodes) == 0 {
		t.Fatal(err)
	}
	return nodes[0], filepath.Join(dir, "chain.rlp")
}
