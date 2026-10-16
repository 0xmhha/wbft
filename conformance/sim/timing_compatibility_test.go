package sim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func timingCompatibilityScenario(t *testing.T, seed int64) Scenario {
	keys := testValidators(t, 4)
	nodes := make([]NodeSpec, 4)
	for i := range nodes {
		nodes[i] = DefaultNode()
	}
	return Scenario{Seed: seed, Validators: keys, Nodes: nodes, Params: Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4}, Until: Stop{Height: 8, Duration: 30 * time.Second}, Schedule: []NodeEvent{{At: 2500 * time.Millisecond, Node: addrOf(keys[3]), Action: ActionStop}, {At: 4 * time.Second, Node: addrOf(keys[3]), Action: ActionRestart}}}
}

// Pin the default timing and observation contract, including event bytes and
// signed headers. SEND records include the signed message view and identity.
// Journal build identities are checked separately within a single binary.
func TestDefaultTimingCompatibility(t *testing.T) {
	for _, test := range []struct {
		seed int64
		hash string
	}{{2, "ca7db6c8c4a9d7a737ce1686788697f594fdc33b9d694a3d8f7fc35ddf4ffa09"}, {7, "9e53ae6a60a73ebf8098857b84bc79e5c2f9c62fdf720ba1a8a323856ea631b5"}} {
		r, err := Run(context.Background(), timingCompatibilityScenario(t, test.seed), Output{})
		if err != nil || len(r.Violations) != 0 {
			t.Fatal(err, r.Violations)
		}
		chain, err := EncodeChain(r.Chain)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(struct {
			Chain    []byte
			Heads    []uint64
			Rounds   map[uint64]uint64
			Events   map[string][]byte
			Duration int64
		}{chain, r.Heads, r.Rounds, r.Events, int64(r.SimTime)})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		got := hex.EncodeToString(digest[:])
		t.Logf("seed=%d sha256=%s", test.seed, got)
		if got != test.hash {
			t.Fatal("default timing behavior changed", test.seed, got)
		}
	}
}
