package sim

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
)

func TestInitialRoundCapNormalSimulation(t *testing.T) {
	for _, flags := range []consensus.ImprovementSet{consensus.ImprovementSet(0).With(consensus.CapInitialRoundTimeout), consensus.KnownImprovements()} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", flags, mixed), func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				cap := uint64(4)
				sc.Params.RequestTimeoutSeconds = 1000
				sc.Params.MaxRequestTimeoutSeconds = &cap
				sc.Until.Duration = 2 * time.Minute
				sc.App.ImportDelay = []time.Duration{time.Millisecond}
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
						t.Fatal("normal capped network did not progress", result.Heads)
					}
				}
			})
		}
	}
}
