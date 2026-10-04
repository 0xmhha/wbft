package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// appBlocks is the test application's chain as a stepdriver.BlockSource.
type appBlocks struct{ a *testApp }

func (b appBlocks) HeaderByNumber(n types.Height) (*types.Header, error) {
	if h := b.a.HeaderByNumber(n.RefLow64()); h != nil { //wbft:low64 HH-60
		return h, nil
	}
	return nil, fmt.Errorf("no block %v", n)
}

func (b appBlocks) BlockByHash(h types.Hash) (*types.Block, error) {
	b.a.mu.Lock()
	defer b.a.mu.Unlock()
	if blk := b.a.byHash[h]; blk != nil {
		return blk, nil
	}
	return nil, fmt.Errorf("no block %x", h)
}

// TestJournalReplay runs a validator with the default journal over a
// restart and replays the journal: every step of both runs gives the
// recorded out_digest.
func TestJournalReplay(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	mem := fsys.NewMem()
	n := startNode(t, a, mem, key, false, nil)
	a.waitHead(t, 3, 20*time.Second)
	stop(t, n)
	head := a.Head().Number.RefLow64() //wbft:low64 HH-60
	n = startNode(t, a, mem, key, false, nil)
	a.waitHead(t, head+2, 20*time.Second)
	stop(t, n)

	recs, err := journal.ReadAll(mem, "/data/journal")
	if err != nil {
		t.Fatal(err)
	}
	runIDs := map[string]bool{}
	for _, r := range recs {
		if s, ok := r.Body.(*journal.SegmentRec); ok {
			runIDs[s.Run] = true
			if s.Self != n.Address() || s.Mode != "embedded" || len(s.Core.ChainConfig) == 0 || len(s.BLSPublicKey) == 0 {
				t.Fatalf("segment record %+v", s.Identity)
			}
		}
	}
	if len(runIDs) != 2 {
		t.Fatalf("segment records of runs %v, want two", runIDs)
	}
	r, err := journal.OpenReader(mem, "/data/journal")
	if err != nil {
		t.Fatal(err)
	}
	steps, starts := 0, 0
	err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: appBlocks{a}}, func(s stepdriver.StepResult) error {
		steps++
		if s.Step == 1 {
			starts++
		}
		if !s.Match {
			return fmt.Errorf("run %d step %d: out_digest differs", s.EngineRun, s.Step)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if steps < 10 || starts != 2 {
		t.Fatalf("replayed %d steps from %d engine starts, want two starts", steps, starts)
	}
}

// TestJournalDisabled keeps no journal directory when the journal is off.
func TestJournalDisabled(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	mem := fsys.NewMem()
	n, err := New(Config{DataDir: "/data", Journal: JournalConfig{Disabled: true}}, Deps{App: a, Authority: a, fs: mem, key: key})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.waitHead(t, 2, 20*time.Second)
	stop(t, n)
	if files := mem.Dump("/data/journal"); len(files) != 0 {
		t.Fatalf("journal files %d", len(files))
	}
	if files := mem.Dump("/data/wal"); len(files) == 0 {
		t.Fatal("no write-ahead log files: the check reads the wrong place")
	}
}
