package sim

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
)

func TestOrderingOptionsNormalSimulation(t *testing.T) {
	for _, flags := range []consensus.ImprovementSet{consensus.ImprovementSet(0).With(consensus.ResetHeightState), consensus.ImprovementSet(0).With(consensus.ScanReadyBacklog), consensus.KnownImprovements()} {
		for _, configuration := range []string{"all", "mixed"} {
			t.Run(fmt.Sprintf("%s/%d", configuration, flags), func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				sc.Until.Duration = 2 * time.Minute
				// Ordinary bounded import delay and the existing normal stop/restart schedule.
				sc.App.ImportDelay = []time.Duration{time.Second}
				for i := range sc.Nodes {
					if configuration == "all" || i%2 == 0 {
						sc.Nodes[i].Options.Improvements |= flags
					}
				}
				result, err := Run(context.Background(), sc, Output{})
				if err != nil || len(result.Violations) != 0 {
					t.Fatal(err, result.Violations)
				}
				for _, head := range result.Heads {
					if head < sc.Until.Height {
						t.Fatal("normal ordered delivery did not progress", result.Heads)
					}
				}
			})
		}
	}
}
