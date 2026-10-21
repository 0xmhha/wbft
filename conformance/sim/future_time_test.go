package sim

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func TestFutureTimePoliciesNormalSimulation(t *testing.T) {
	for _, flags := range []consensus.ImprovementSet{
		consensus.ImprovementSet(0).With(consensus.UseFutureTimeAllowance),
		consensus.ImprovementSet(0).With(consensus.LimitFutureProposalWait),
		consensus.ImprovementSet(0).With(consensus.UseFutureTimeAllowance).With(consensus.LimitFutureProposalWait),
		consensus.KnownImprovements(),
	} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", flags, mixed), func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				sc.Params.AllowedFutureBlockTime = timingValue(2)
				sc.Until.Duration = 2 * time.Minute
				sc.App.ImportDelay = []time.Duration{time.Millisecond}
				sc.Nodes[1].ClockSkew = 300 * time.Millisecond
				for i := range sc.Nodes {
					if !mixed || i%2 == 0 {
						sc.Nodes[i].Options.Improvements |= flags
					}
				}
				result, err := Run(context.Background(), sc, Output{})
				if err != nil || len(result.Violations) != 0 || result.Refusals != 0 {
					t.Fatal(err, result.Violations, result.Refusals)
				}
				for _, head := range result.Heads {
					if head < sc.Until.Height {
						t.Fatal("normal future-time network did not progress", result.Heads)
					}
				}
			})
		}
	}
}

// A normally finalized header primes the shared verification cache. Another
// node with the same configured transition must still use its selected policy.
func TestFutureTimeVerificationCacheKeepsNodePolicy(t *testing.T) {
	sc := timingCompatibilityScenario(t, 7)
	sc.Schedule = nil
	sc.Until.Height = 1
	sc.Params.AllowedFutureBlockTime = timingValue(1)
	result, err := Run(context.Background(), sc, Output{})
	if err != nil || len(result.Chain) < 2 {
		t.Fatal(err)
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	b := result.Chain[1]
	for _, n := range s.nodes {
		var config map[string]json.RawMessage
		if err = json.Unmarshal(n.cfgJSON, &config); err != nil {
			t.Fatal(err)
		}
		config["transitions"] = json.RawMessage(`[{"block":1,"allowedFutureBlockTime":3}]`)
		n.cfgJSON, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		n.cfg, err = types.ParseChainConfig(n.cfgJSON)
		if err != nil {
			t.Fatal(err)
		}
		n.cfgHash = keccak.Sum256(n.cfgJSON)
		n.clock = &nodeClock{l: &s.l, origin: time.Unix(int64(b.Header.Time)-2, 0), live: func() bool { return true }}
	}
	s.nodes[0].spec.Options.Improvements = s.nodes[0].spec.Options.Improvements.With(consensus.UseFutureTimeAllowance)
	if err = s.nodes[0].app.importBlock(b, "imported"); err != nil {
		t.Fatal("selected transition policy did not prime cache", err)
	}
	if err = s.nodes[1].app.importBlock(b, "imported"); err == nil || s.nodes[1].head() != 0 {
		t.Fatal("cached selected policy bypassed another node's H2")
	}
	if len(s.verified) != 1 {
		t.Fatal("failed time verification entered cache")
	}
}
