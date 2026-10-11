package sim

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

// round0Proposer returns the proposer of the block decided at height h in a
// run without faults.
func round0Proposer(t *testing.T, vs []Validator, h uint64) types.Address {
	t.Helper()
	res, err := Run(context.Background(), Scenario{Name: "probe", Seed: 1, Validators: vs, Until: Stop{Height: h, Duration: time.Minute}}, Output{})
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(res.Chain)) <= h || res.Rounds[h] != 0 {
		t.Fatalf("height %d not decided in round 0: rounds %v", h, res.Rounds)
	}
	return res.Chain[h].Header.Coinbase
}

// A block that gathers a COMMIT quorum and then fails import at every node
// is released by the bad-block rule: every node sends a ROUND-CHANGE of the
// height without a prepared pair although it signed a COMMIT for the block.
// The private validator signs that ROUND-CHANGE, and the height is decided
// in a later round.
func TestBadBlockAfterCommit(t *testing.T) {
	vs := testValidators(t, 4)
	p := round0Proposer(t, vs, 2)
	for _, tt := range []struct {
		name  string
		delay time.Duration
	}{
		// The import fails before the round timer of round 0 expires.
		{"import fails at once", 0},
		// The import fails after the round timer of round 0 expired: the
		// ROUND-CHANGE of round 1 still carries the prepared pair, and the
		// pair is released at the next round change.
		{"import fails after the round timeout", 4 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sc := Scenario{Name: "bad_block_after_commit", Seed: 1, Validators: vs, Until: Stop{Height: 4, Duration: 2 * time.Minute},
				App: AppModel{FailedImports: []FailedImport{{Height: 2, Proposer: p, Delay: tt.delay}}}}
			dir := t.TempDir()
			res, err := Run(context.Background(), sc, Output{EventsDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			// Every node records the failed import of the block as bad.
			bad := importFails(t, dir)
			if len(bad) != len(vs) {
				t.Errorf("IMPORT_FAIL records of %d nodes, want %d: %v", len(bad), len(vs), bad)
			}
			for node, recs := range bad {
				if recs[0] != "2 sealed_locally true" {
					t.Errorf("node %s: IMPORT_FAIL %v", node, recs)
				}
			}
			if len(res.Violations) != 0 {
				t.Fatalf("violations %v (heads %v, rounds %v, refusals %d)", res.Violations, res.Heads, res.Rounds, res.Refusals)
			}
			if res.Refusals != 0 {
				t.Errorf("%d signatures refused", res.Refusals)
			}
			if res.Rounds[2] == 0 {
				t.Errorf("height 2 decided in round 0: rounds %v", res.Rounds)
			}
			if res.Chain[2].Header.Coinbase == p {
				t.Errorf("the block that failed import was decided again")
			}
			t.Logf("heads %v rounds %v", res.Heads, res.Rounds)
		})
	}
}

// importFails returns, per node, the "number path recorded_bad" of its
// IMPORT_FAIL records in the event files of dir.
func importFails(t *testing.T, dir string) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("event files: %v %v", files, err)
	}
	out := map[string][]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var r struct {
				Node, Kind, Number, Path string
				RecordedBad              bool `json:"recorded_bad"`
			}
			if err := json.Unmarshal([]byte(l), &r); err != nil {
				t.Fatal(err)
			}
			if r.Kind == "IMPORT_FAIL" {
				out[r.Node] = append(out[r.Node], fmt.Sprintf("%s %s %v", r.Number, r.Path, r.RecordedBad))
			}
		}
	}
	return out
}
