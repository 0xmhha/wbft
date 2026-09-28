package stepdriver_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func keys(n int) []sim.Validator {
	out := make([]sim.Validator, n)
	for i := range out {
		out[i] = sim.Validator{ECDSA: keccak.Sum256Bytes([]byte("wbft-replay-key-" + strconv.Itoa(i)))}
	}
	return out
}

// replayScenarios are the scenarios of the replay tests: every template of
// the bundle, a few seeds each.
func replayScenarios(t *testing.T) []sim.Scenario {
	n := 2
	if s := os.Getenv("WBFT_REPLAY_SEEDS"); s != "" {
		var err error
		if n, err = strconv.Atoi(s); err != nil {
			t.Fatal(err)
		}
	}
	ks := keys(7)
	var out []sim.Scenario
	for _, tpl := range sim.Bundle() {
		for seed := int64(0); seed < int64(n); seed++ {
			out = append(out, tpl.Make(seed, ks))
		}
	}
	return out
}

// memJournal loads journal files into a memory file system.
func memJournal(t *testing.T, files map[string][]byte) (*fsys.Mem, string) {
	fs := fsys.NewMem()
	dir := "/j"
	if err := fs.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedNames(files) {
		f, err := fs.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	return fs, dir
}

func sortedNames(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// trace replays one journal and returns the encoded outputs and variables
// of every step; it fails on a step that does not match the record.
func trace(t *testing.T, fs *fsys.Mem, dir string, blocks stepdriver.BlockSource) ([][]byte, int) {
	t.Helper()
	r, err := journal.OpenReader(fs, dir)
	if err != nil {
		t.Fatal(err)
	}
	var encs [][]byte
	steps := 0
	err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: blocks, WithVars: true}, func(s stepdriver.StepResult) error {
		steps++
		if !s.Match {
			t.Errorf("engine run %d step %d (%s): replayed outputs differ from the record", s.EngineRun, s.Step, inputlog.Kind(s.Input))
		}
		enc, err := inputlog.EncodeOutputs(s.Outputs)
		if err != nil {
			return err
		}
		encs = append(encs, enc, []byte(varsString(s)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return encs, steps
}

func varsString(s stepdriver.StepResult) string {
	if s.Vars == nil {
		return "nil"
	}
	return stepdriver.VarsJSON(s.Vars)
}

// TestReplayDeterminism: the same seed gives byte-identical journals and
// event files, and every node journal replays through the core twice with
// every step matching its recorded out_digest and with identical outputs
// and state variables in both replays.
func TestReplayDeterminism(t *testing.T) {
	var mu sync.Mutex
	steps, nodes := 0, 0
	start := time.Now()
	t.Run("scenarios", func(t *testing.T) {
		for _, sc := range replayScenarios(t) {
			sc := sc
			t.Run(sc.Name+"/"+strconv.FormatInt(sc.Seed, 10), func(t *testing.T) {
				t.Parallel()
				n, s := checkReplay(t, sc)
				mu.Lock()
				nodes += n
				steps += s
				mu.Unlock()
			})
		}
	})
	t.Logf("%d node journals, %d steps replayed in %s", nodes, steps, time.Since(start).Round(time.Millisecond))
	if steps == 0 {
		t.Fatal("nothing replayed")
	}
}

func checkReplay(t *testing.T, sc sim.Scenario) (nodes, steps int) {
	a, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Violations) != 0 {
		t.Fatalf("%v", a.Violations)
	}
	for name, data := range a.Events {
		if !bytes.Equal(data, b.Events[name]) {
			t.Fatalf("event file %s differs between two runs", name)
		}
	}
	src, err := sim.NewChainSource(a.Chain)
	if err != nil {
		t.Fatal(err)
	}
	for node, files := range a.Journals {
		other := b.Journals[node]
		for name, data := range files {
			if !bytes.Equal(data, other[name]) {
				t.Fatalf("journal file %s of %x differs between two runs", name, node[:4])
			}
		}
		fs, dir := memJournal(t, files)
		r1, n := trace(t, fs, dir, src)
		r2, _ := trace(t, fs, dir, src)
		if len(r1) != len(r2) {
			t.Fatalf("replays of %x differ in length", node[:4])
		}
		for i := range r1 {
			if !bytes.Equal(r1[i], r2[i]) {
				t.Fatalf("node %x: replays differ at record %d", node[:4], i)
			}
		}
		steps += n
		nodes++
	}
	return nodes, steps
}

// TestJournalExport writes the journals of the replay scenarios to
// WBFT_JOURNAL_OUT for a replay on another machine.
func TestJournalExport(t *testing.T) {
	out := os.Getenv("WBFT_JOURNAL_OUT")
	if out == "" {
		t.Skip("WBFT_JOURNAL_OUT not set")
	}
	for i, sc := range replayScenarios(t) {
		dir := filepath.Join(out, strconv.Itoa(i)+"-"+sc.Name)
		if _, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestJournalImport replays the journals under WBFT_JOURNAL_IN (written by
// TestJournalExport, possibly on another architecture); every step must
// match its recorded out_digest.
func TestJournalImport(t *testing.T) {
	in := os.Getenv("WBFT_JOURNAL_IN")
	if in == "" {
		t.Skip("WBFT_JOURNAL_IN not set")
	}
	runs, err := os.ReadDir(in)
	if err != nil {
		t.Fatal(err)
	}
	steps := 0
	for _, e := range runs {
		if !e.IsDir() {
			continue
		}
		nodes, chain, err := sim.ReadJournalDir(filepath.Join(in, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src, err := sim.NewChainSource(chain)
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range nodes {
			r, err := journal.OpenReader(fsys.OS{}, dir)
			if err != nil {
				t.Fatal(err)
			}
			err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: src}, func(s stepdriver.StepResult) error {
				steps++
				if !s.Match {
					t.Errorf("%s: engine run %d step %d does not match", dir, s.EngineRun, s.Step)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if steps == 0 {
		t.Fatal("no steps replayed")
	}
	t.Logf("%d steps replayed", steps)
}
