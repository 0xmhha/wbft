package sim

import (
	"context"
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
			res, err := Run(context.Background(), sc, Output{})
			if err != nil {
				t.Fatal(err)
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
