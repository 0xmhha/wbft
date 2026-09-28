package stepdriver

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// vectorsDir returns the vector directory named by WBFT_SPEC_VECTORS (the
// "vectors" directory of the specification), or skips the test.
func vectorsDir(t *testing.T) string {
	dir := os.Getenv("WBFT_SPEC_VECTORS")
	if dir == "" {
		t.Skip("WBFT_SPEC_VECTORS is not set")
	}
	return dir
}

// loadCase reads input.yaml and expected.yaml of a steps case converted to
// JSON by the helper in testdata (the vector files use a YAML subset that
// maps one to one to JSON).
func loadCase(t *testing.T, dir string) (input json.RawMessage, expected any) {
	t.Helper()
	in, err := yamlSubsetToJSON(filepath.Join(dir, "input.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ex, err := yamlSubsetToJSON(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var e any
	if err := json.Unmarshal(ex, &e); err != nil {
		t.Fatal(err)
	}
	return in, e
}

func runVectors(t *testing.T, handler, sub string, opts Options, allowUnsupported bool) {
	root := filepath.Join(vectorsDir(t), sub)
	cases, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name(), func(t *testing.T) {
			input, want := loadCase(t, filepath.Join(root, c.Name()))
			got, err := Run(handler, input, opts)
			if errors.Is(err, ErrUnsupported) && allowUnsupported {
				t.Skip("unsupported without a frame stage")
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var g any
			if err := json.Unmarshal(raw, &g); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(g, want) {
				t.Errorf("output differs\n got %s", raw)
			}
		})
	}
}

func TestRoundsVectors(t *testing.T) {
	runVectors(t, HandlerRounds, "state_machine/rounds", Options{}, false)
}

func TestReceiveOutcomeVectorsWithoutFrameStage(t *testing.T) {
	runVectors(t, HandlerReceiveOutcome, "network/receive_outcome", Options{}, true)
}

// With the frame verdicts of package transport as the frame stage, every
// network case is decided.
func TestReceiveOutcomeVectorsWithFrameStage(t *testing.T) {
	runVectors(t, HandlerReceiveOutcome, "network/receive_outcome", Options{Frame: transportFrame}, false)
}
