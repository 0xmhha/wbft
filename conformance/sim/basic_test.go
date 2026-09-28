package sim

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/0xmhha/wbft/crypto/keccak"
)

func testValidators(t testing.TB, n int) []Validator {
	t.Helper()
	out := make([]Validator, n)
	for i := range out {
		out[i] = Validator{ECDSA: keccak.Sum256Bytes([]byte("wbft-sim-key-" + strconv.Itoa(i)))}
	}
	return out
}

func TestNormalProgress(t *testing.T) {
	start := time.Now()
	res, err := Run(context.Background(), Scenario{Name: "normal", Seed: 1, Validators: testValidators(t, 4), Until: Stop{Height: 5, Duration: time.Minute}}, Output{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("heads %v rounds %v violations %v simtime %s wall %s", res.Heads, res.Rounds, res.Violations, res.SimTime, time.Since(start))
	if len(res.Violations) != 0 {
		t.Fatal(res.Violations)
	}
}

func TestCrashRestart(t *testing.T) {
	vs := testValidators(t, 4)
	for seed := int64(1); seed <= 20; seed++ {
		v1 := mustAddr(t, vs[1])
		sc := Scenario{Name: "crash", Seed: seed, Validators: testValidators(t, 4), Until: Stop{Height: 8, Duration: 2 * time.Minute},
			Schedule: []NodeEvent{{At: 2500 * time.Millisecond, Node: v1, Action: ActionCrash}, {At: 4 * time.Second, Node: v1, Action: ActionRestart}}}
		res, err := Run(context.Background(), sc, Output{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Violations) != 0 {
			t.Fatalf("seed %d: %v (heads %v, replays %+v)", seed, res.Violations, res.Heads, res.Replays)
		}
		t.Logf("seed %d heads %v rounds %v replays %+v", seed, res.Heads, res.Rounds, res.Replays[len(res.Replays)-1])
	}
}

func mustAddr(t testing.TB, v Validator) (a [20]byte) {
	x, err := NewValidator(v.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	return x.Address()
}
