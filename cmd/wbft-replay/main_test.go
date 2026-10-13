package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/journal"
)

func export(t *testing.T) (journalDir, chain string) {
	dir := t.TempDir()
	var ks []sim.Validator
	for i := 0; i < 4; i++ {
		ks = append(ks, sim.Validator{ECDSA: keccak.Sum256Bytes([]byte("replay-cmd-" + strconv.Itoa(i)))})
	}
	sc := sim.Bundle()[0].Make(3, ks)
	res, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil || len(res.Violations) != 0 {
		t.Fatal(err, res.Violations)
	}
	nodes, _, err := sim.ReadJournalDir(dir)
	if err != nil || len(nodes) == 0 {
		t.Fatal(err)
	}
	return nodes[0], filepath.Join(dir, "chain.rlp")
}

func TestReplayOnce(t *testing.T) {
	jd, chain := export(t)
	var out bytes.Buffer
	if code := replayOnce(jd, chain, false, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "mismatches 0") {
		t.Fatal(out.String())
	}
}

func TestProtocol(t *testing.T) {
	jd, chain := export(t)
	in := fmt.Sprintf(`{"type":"hello","protocol":"wbft-replay/1"}
{"type":"replay","id":7,"journal":%q,"chain":%q,"with_vars":true,"from_step":2,"to_step":4}
{"type":"replay","id":8,"journal":"/nonexistent","chain":%q}
{"type":"bye"}
`, jd, chain, chain)
	var out bytes.Buffer
	if err := serve(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var types []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		types = append(types, m["type"].(string))
		if m["type"] == "step" && m["match"] != true {
			t.Fatalf("step does not match: %v", m)
		}
		if m["type"] == "hello" {
			v, ok := m["version"].(string)
			if !ok || v == "" {
				t.Fatal("helper version unavailable", m)
			}
		}
		if m["type"] == "error" && m["code"] != "replay_error" {
			t.Fatal("missing structured replay error", m)
		}
		if m["type"] == "done" && m["mismatches"].(float64) != 0 {
			t.Fatal(m)
		}
	}
	if strings.Join(types, ",") != "hello,step,step,step,done,error" {
		t.Fatalf("answers %v", types)
	}
}

// TestReplayBundle replays a journal bundle (wbft-journal export) of a
// simulator node: the same steps as the journal directory, no mismatch.
func TestReplayBundle(t *testing.T) {
	jd, chain := export(t)
	bundle := filepath.Join(t.TempDir(), "node.tar")
	f, err := os.Create(bundle)
	if err != nil {
		t.Fatal(err)
	}
	m, err := journal.WriteBundle(nil, jd, f, journal.BundleOptions{})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || !m.StartsAtRunStart {
		t.Fatalf("bundle %+v: %v", m, err)
	}
	var fromDir, fromBundle bytes.Buffer
	if code := replayOnce(jd, chain, false, &fromDir); code != 0 {
		t.Fatalf("directory: exit %d: %s", code, fromDir.String())
	}
	if code := replayOnce(bundle, chain, false, &fromBundle); code != 0 {
		t.Fatalf("bundle: exit %d: %s", code, fromBundle.String())
	}
	if fromBundle.String() != fromDir.String() || !strings.Contains(fromBundle.String(), "mismatches 0") {
		t.Fatalf("bundle replay %q, directory replay %q", fromBundle.String(), fromDir.String())
	}
}

func TestContextAnswerProtocolAndCLIKeepCounterfactualStatus(t *testing.T) {
	jd, chain := export(t)
	var out bytes.Buffer
	if code := replayOnceTrace(jd, chain, false, stepdriver.TraceOptions{AnswerScope: "context"}, &out); code != 3 || !strings.Contains(out.String(), "original reproduction is not established") {
		t.Fatal(code, out.String())
	}
	input := fmt.Sprintf(`{"type":"hello","protocol":"wbft-replay/1"}
{"type":"replay","id":9,"journal":%q,"chain":%q,"answer_scope":"context"}
{"type":"replay","id":10,"journal":%q,"chain":%q,"answer_scope":"unbounded"}
{"type":"bye"}
`, jd, chain, jd, chain)
	out.Reset()
	if err := serve(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&out)
	done, sourceCalls, refused := false, 0, false
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		switch row["type"] {
		case "step":
			if row["context_answers"] != true || row["match"] != true {
				t.Fatal(row)
			}
			if sources, ok := row["answer_sources"].([]any); ok {
				sourceCalls += len(sources)
			}
		case "done":
			if row["counterfactual"] != true || row["answer_scope"] != "context" || row["mismatches"] != float64(0) {
				t.Fatal(row)
			}
			done = true
		case "error":
			if row["id"] != float64(10) || row["code"] != "env_source_mismatch" {
				t.Fatal(row)
			}
			refused = true
		}
	}
	if !done || sourceCalls == 0 || !refused {
		t.Fatal(done, sourceCalls, refused)
	}
}

func TestInputScheduleProtocolMarksOriginalCoordinatesAndCounterfactual(t *testing.T) {
	jd, chain := export(t)
	records, err := journal.ReadAll(nil, jd)
	if err != nil {
		t.Fatal(err)
	}
	writer := ""
	var target *journal.StepRec
	for _, r := range records {
		if seg, ok := r.Body.(*journal.SegmentRec); ok {
			writer = seg.Run
		}
		if b, ok := r.Body.(*journal.StepRec); ok && b.InputKind == inputlog.KindCapturedMessage {
			target = b
			break
		}
	}
	if target == nil {
		t.Fatal("no captured input")
	}
	schedule := &stepdriver.TraceSchedule{Action: "drop", WriterRun: writer, EngineRun: target.EngineRun, Step: target.Step}
	request, _ := json.Marshal(map[string]any{"type": "replay", "id": 12, "journal": jd, "chain": chain, "answer_scope": "context", "input_schedule": schedule, "to_step": target.Step})
	var out bytes.Buffer
	if err := serve(bytes.NewReader(append(request, '\n')), &out); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&out)
	found, done := false, false
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		switch row["type"] {
		case "step":
			position, ok := row["scheduled_input"].(map[string]any)
			if !ok || position["writer_run"] != writer || position["step"] != row["step"] || position["source_seq"] == nil {
				t.Fatal(row)
			}
			if row["step"] == float64(target.Step) {
				found = true
				if row["omitted"] != true || row["suppression_reason"] != "requested_drop" {
					t.Fatal(row)
				}
			}
		case "done":
			done = true
			if row["counterfactual"] != true || row["input_schedule"] == nil {
				t.Fatal(row)
			}
		case "error":
			t.Fatal(row)
		}
	}
	if !found || !done {
		t.Fatal(found, done, out.String())
	}
}
