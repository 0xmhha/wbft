package sim

import (
	"context"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/consensus"
)

func TestKeepStoppedPeersNormalSimulation(t *testing.T) {
	for _, flags := range []consensus.ImprovementSet{consensus.ImprovementSet(0).With(consensus.KeepStoppedPeers), consensus.KnownImprovements()} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", flags, mixed), func(t *testing.T) {
				sc := timingCompatibilityScenario(t, 7)
				sc.Params.EpochLength = 2
				for i := range sc.Nodes {
					if !mixed || i%2 == 0 {
						sc.Nodes[i].Options.Improvements |= flags
					}
				}
				r, err := Run(context.Background(), sc, Output{})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Violations) != 0 || r.Refusals != 0 {
					t.Fatal(r.Violations, r.Refusals)
				}
				for _, head := range r.Heads {
					if head < sc.Until.Height {
						t.Fatal("normal network did not resume progress", r.Heads)
					}
				}
			})
		}
	}
}
