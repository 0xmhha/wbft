package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"os"
)

func prunedCommandJournal(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	keys := make([]sim.Validator, 4)
	for i := range keys {
		keys[i] = sim.Validator{ECDSA: keccak.Sum256Bytes([]byte("bounded-command-" + strconv.Itoa(i)))}
	}
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-command-warmup", Seed: 4, Validators: keys, Until: sim.Stop{Height: 5, Duration: time.Minute}}, sim.Output{JournalDir: dir})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	nodes, _, err := sim.ReadJournalDir(dir)
	if err != nil || len(nodes) == 0 {
		t.Fatal(err)
	}
	reader, err := journal.OpenReader(nil, nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	first, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "journal")
	writer, err := journal.Open(journal.Options{Dir: target, SegmentBytes: 2048, Synchronous: true}, first.Body.(*journal.SegmentRec).Identity)
	if err != nil {
		t.Fatal(err)
	}
	for {
		rec, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if s, ok := rec.Body.(*journal.StepRec); ok {
			if s.InputKind == inputlog.KindStart {
				continue
			}
			writer.NoteHead(s.HeadNumber)
		}
		writer.Put(rec)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return target, filepath.Join(dir, "chain.rlp")
}

func TestApproximateCLIHasDistinctExitAndProtocolLabels(t *testing.T) {
	dir, chain := prunedCommandJournal(t)
	var closed, approx bytes.Buffer
	if code := replayOnce(dir, chain, false, &closed); code != 2 {
		t.Fatal("zero-step closed replay reported success", code, closed.String())
	}
	opts := stepdriver.TraceOptions{Warmup: &stepdriver.TraceWarmup{FromHeight: 1, CompareFromHeight: 3}}
	if code := replayOnceTrace(dir, chain, false, opts, &approx); code != 3 || !strings.Contains(approx.String(), "original reproduction is not established") {
		t.Fatal(code, approx.String())
	}
	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, request := range []map[string]any{{"type": "hello", "protocol": Protocol}, {"type": "replay", "id": 7, "journal": dir, "chain": chain, "warmup_from_height": 1, "compare_from_height": 3}, {"type": "bye"}} {
		if err := enc.Encode(request); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := serve(&input, &output); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&output)
	counts := [2]int{}
	hello, done := false, false
	for scanner.Scan() {
		var r map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		switch r["type"] {
		case "hello":
			features, _ := r["features"].([]any)
			found := false
			for _, f := range features {
				if f == "bounded_warmup_v1" {
					found = true
				}
			}
			if !found {
				t.Fatal("capability missing", r)
			}
			hello = true
		case "step":
			if r["approximate"] != true || r["input"] == "start" || r["writer_run"] == "" {
				t.Fatal("approximation hidden", r)
			}
			if r["warmup"] == true {
				counts[0]++
			} else {
				counts[1]++
			}
		case "done":
			if r["approximate_steps"].(float64) != float64(counts[0]+counts[1]) || r["warmup_steps"].(float64) != float64(counts[0]) {
				t.Fatal("prefix totals changed", r, counts)
			}
			done = true
		case "error":
			t.Fatal("unexpected failure", r)
		}
	}
	if scanner.Err() != nil || !hello || !done || counts[0] == 0 || counts[1] == 0 {
		t.Fatal(scanner.Err(), hello, done, counts)
	}
}

func TestPartialBundleNeedsExplicitBoundedWarmup(t *testing.T) {
	dir, chain := prunedCommandJournal(t)
	path := filepath.Join(t.TempDir(), "partial.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	from, to := types.HeightFromUint64(4), types.HeightFromUint64(5)
	manifest, err := journal.WriteBundle(nil, dir, file, journal.BundleOptions{From: &from, To: &to, Warmup: 2})
	closed := file.Close()
	if err != nil || closed != nil {
		t.Fatal(err, closed)
	}
	if manifest.StartsAtRunStart {
		t.Fatal("fixture did not export a partial writer run")
	}
	var refused, approx bytes.Buffer
	if code := replayOnce(path, chain, false, &refused); code != 2 {
		t.Fatal("partial bundle accepted as exact", code, refused.String())
	}
	if code := replayOnceTrace(path, chain, false, stepdriver.TraceOptions{Warmup: &stepdriver.TraceWarmup{FromHeight: 2, CompareFromHeight: 4}}, &approx); code != 3 {
		t.Fatal("explicit partial-bundle replay unavailable", code, approx.String())
	}
}
