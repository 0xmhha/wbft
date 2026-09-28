package stepdriver

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/privval"
)

// The steps vectors run with every optional behaviour off. A node runs the
// core with consensus.RestartSafety and signs through its private validator.
// These tests run the same cases the node's way and compare the result with
// the expected output of the vectors.

type refusal struct {
	step int
	code codec.Code
	seq  string
	err  error
}

type stepsCase struct {
	handler, name string
	input         json.RawMessage
	want          any
}

func stepsCases(t *testing.T) []stepsCase {
	var out []stepsCase
	for _, sub := range []struct{ handler, dir string }{
		{HandlerRounds, "state_machine/rounds"},
		{HandlerReceiveOutcome, "network/receive_outcome"},
	} {
		root := filepath.Join(vectorsDir(t), sub.dir)
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			input, want := loadCase(t, filepath.Join(root, e.Name()))
			out = append(out, stepsCase{sub.handler, sub.dir + "/" + e.Name(), input, want})
		}
	}
	return out
}

// runAs runs c with opts and the frame stage of package transport, and
// returns the output as generic JSON and the refused signatures.
func runAs(t *testing.T, c stepsCase, opts Options) (any, []refusal) {
	t.Helper()
	var refs []refusal
	opts.Frame = transportFrame
	opts.Refused = func(step int, m *codec.Message, err error) {
		refs = append(refs, refusal{step, m.Code, m.View.Sequence.String(), err})
	}
	got, err := Run(c.handler, c.input, opts)
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g any
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g, refs
}

// stepRecords returns the step records of a case output.
func stepRecords(out any) []any {
	m, _ := out.(map[string]any)
	s, _ := m["steps"].([]any)
	return s
}

// With the restart-safety rules on, every steps case sends and records
// exactly what the reference does: no vector restarts the node, so the
// write-ahead log replay has nothing to restore, no case makes the core
// build a second round-0 proposal, and the private validator signs every
// message the core sends.
func TestVectorsWithRestartSafety(t *testing.T) {
	for _, c := range stepsCases(t) {
		got, refs := runAs(t, c, Options{Improvements: consensus.RestartSafety, PrivVal: true})
		if len(refs) != 0 {
			t.Errorf("%s: refused %+v", c.name, refs)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: output differs from the reference", c.name)
		}
	}
}

// Without the bad-block release mark the private validator refuses the
// ROUND-CHANGE of bad_block_unlock: the node signed a COMMIT in round 0 and
// the bad-block rule released the prepared pair, so the ROUND-CHANGE of
// round 1 carries none. It is the only case the mark changes, and the only
// difference is that ROUND-CHANGE.
func TestVectorsWithoutBadBlockReleaseMark(t *testing.T) {
	guard := consensus.ImprovementSet(0).With(consensus.OneRound0Proposal)
	var differ []string
	for _, c := range stepsCases(t) {
		got, refs := runAs(t, c, Options{Improvements: guard, PrivVal: true})
		if reflect.DeepEqual(got, c.want) && len(refs) == 0 {
			continue
		}
		differ = append(differ, c.name)
		if len(refs) != 1 || refs[0].code != codec.CodeRoundChange || !errors.Is(refs[0].err, privval.ErrDoubleSign) {
			t.Errorf("%s: refused %+v", c.name, refs)
			continue
		}
		gs, ws := stepRecords(got), stepRecords(c.want)
		for i := range ws {
			g, w := gs[i].(map[string]any), ws[i].(map[string]any)
			if i != refs[0].step {
				if !reflect.DeepEqual(g, w) {
					t.Errorf("%s: step %d differs", c.name, i)
				}
				continue
			}
			sent, _ := w["sent"].([]any)
			if len(sent) != 1 || len(g["sent"].([]any)) != 0 {
				t.Errorf("%s: step %d sends %v, reference %v", c.name, i, g["sent"], sent)
			}
			delete(g, "sent")
			delete(w, "sent")
			if !reflect.DeepEqual(g, w) {
				t.Errorf("%s: step %d differs beyond the refused ROUND-CHANGE", c.name, i)
			}
		}
	}
	if !slices.Equal(differ, []string{"state_machine/rounds/bad_block_unlock"}) {
		t.Errorf("cases that differ without the mark: %v", differ)
	}
}

// A node that took over its key without the sign record starts with the sign
// floor at head + 1: it signs nothing at that height, and every refusal is a
// sign-floor refusal. Cases that reach the next height send there.
func TestVectorsWithSignFloor(t *testing.T) {
	for _, c := range stepsCases(t) {
		in, err := parseInput(c.input)
		if err != nil {
			t.Fatal(err)
		}
		head, err := codec.DecodeBlock(in.Initial.Head)
		if err != nil {
			t.Fatal(err)
		}
		floor := head.Header.Number.AddUint64(1)
		got, refs := runAs(t, c, Options{Improvements: consensus.RestartSafety, PrivVal: true, SignFloor: true})
		for _, r := range refs {
			if !errors.Is(r.err, privval.ErrBelowSignFloor) || r.seq != floor.String() {
				t.Errorf("%s: step %d at %s: %v", c.name, r.step, r.seq, r.err)
			}
		}
		for i, s := range stepRecords(got) {
			sent, _ := s.(map[string]any)["sent"].([]any)
			for _, m := range sent {
				if seq, _ := m.(map[string]any)["sequence"].(string); seq == floor.String() {
					t.Errorf("%s: step %d sends at the floor height %s", c.name, i, seq)
				}
			}
		}
	}
}
