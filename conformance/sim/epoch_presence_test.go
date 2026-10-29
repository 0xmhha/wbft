package sim

import (
	"context"
	"github.com/0xmhha/wbft/consensus"
	"testing"
	"time"
)

func TestEpochPresenceNormalMixedSimulationAndCache(t *testing.T) {
	sc := timingCompatibilityScenario(t, 7)
	sc.Schedule = nil
	for index := range sc.Nodes {
		if index%2 == 0 {
			sc.Nodes[index].Options.Improvements = sc.Nodes[index].Options.Improvements.With(consensus.CheckEpochInfoPresence)
		}
	}
	result, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 || result.Refusals != 0 {
		t.Fatal("normal mixed policy progress", result.Violations, result.Refusals)
	}
	for _, head := range result.Heads {
		if head < sc.Until.Height {
			t.Fatal("normal network stopped", result.Heads)
		}
	}
	if len(result.Chain) < 2 {
		t.Fatal("normal source block missing")
	}
	fresh, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	block := result.Chain[1]
	for _, n := range fresh.nodes {
		n.clock = &nodeClock{l: &fresh.l, origin: time.Unix(int64(block.Header.Time), 0), live: func() bool { return true }}
	}
	if !fresh.nodes[0].app.env().CheckEpochInfoPresence || fresh.nodes[1].app.env().CheckEpochInfoPresence {
		t.Fatal("simulation Env lost each node's selected policy")
	}
	if err = fresh.nodes[0].app.importBlock(block, "imported"); err != nil {
		t.Fatal("selected normal import", err)
	}
	if err = fresh.nodes[1].app.importBlock(block, "imported"); err != nil {
		t.Fatal("unselected normal import", err)
	}
	if len(fresh.verified) != 2 {
		t.Fatal("distinct policies shared the header cache", len(fresh.verified))
	}
	seen := map[bool]int{}
	for key := range fresh.verified {
		seen[key.CheckEpochInfoPresence]++
	}
	if seen[false] != 1 || seen[true] != 1 {
		t.Fatal("normal cached proof did not retain policy", seen)
	}
}
