package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestProposalAuthorNormalNodeRestartAndReplay(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			key := testKey(0)
			raw, g := testGenesis(t, key)
			a := newTestApp(raw, g)
			mem := fsys.NewMem()
			events := &syncBuffer{}
			var names []string
			if enabled {
				names = []string{"bind_fresh_proposal_author"}
			}
			start := func() *Node {
				n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a, fs: mem, key: key, Events: events})
				if err != nil {
					t.Fatal(err)
				}
				a.cons = n.Consensus()
				if err = n.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if n.running() {
						stop(t, n)
					}
				})
				return n
			}
			n := start()
			a.waitHead(t, 3, 20*time.Second)
			stop(t, n)
			prior := a.Head().Number
			n = start()
			a.waitHead(t, prior.AddUint64(2).RefLow64(), 20*time.Second) //wbft:low64 HH-60
			stop(t, n)
			found := false
			for _, i := range (backend{n}).NodeInfo().Improvements {
				if i.Name == "bind_fresh_proposal_author" && i.Source == "node" {
					found = true
				}
			}
			if found != enabled {
				t.Fatal("node option declaration", found, enabled)
			}
			records, err := journal.ReadAll(mem, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			segments := 0
			for _, record := range records {
				if segment, ok := record.Body.(*journal.SegmentRec); ok {
					segments++
					if consensus.ImprovementSet(segment.Core.Improvements).Has(consensus.BindFreshProposalAuthor) != enabled {
						t.Fatal("journal option lost")
					}
				}
			}
			if segments < 2 {
				t.Fatal("missing run metadata", segments)
			}
			reader, err := journal.OpenReader(mem, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			steps, starts := 0, 0
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: appBlocks{a}}, func(s stepdriver.StepResult) error {
				steps++
				if s.Step == 1 {
					starts++
				}
				if !s.Match {
					return fmt.Errorf("replay mismatch in run %d step %d", s.EngineRun, s.Step)
				}
				return nil
			})
			if err != nil || steps < 10 || starts != 2 {
				t.Fatal("normal node replay", err, steps, starts)
			}
			checkEvents([]byte(events.String()))
		})
	}
}
