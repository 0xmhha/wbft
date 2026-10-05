package node

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/types"
)

// TestCountedSnaps counts a parent missing from the snapshot cache once per
// verification and context, whatever the number of lookups, and not a hit;
// a reader without a context counts nothing.
func TestCountedSnaps(t *testing.T) {
	cache := source.NewCache(4)
	held := types.Hash{1}
	tip, err := source.GasTipFromBig(new(big.Int))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := source.NewAuthoritySnapshot(types.HeightFromUint64(1), held, tip, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache.Put(snap)
	reg := metrics.NewRegistry()
	misses := reg.Counter("wbft_authority_cache_misses_total", "", "context")
	c := &chainView{snaps: cache, misses: misses}

	pre := c.snapshots("preprepare")
	for range 2 { // H15b and H21
		if _, ok := pre.Get(types.Hash{2}); ok {
			t.Fatal("a missing snapshot found")
		}
	}
	if _, ok := pre.Get(held); !ok {
		t.Fatal("a held snapshot missed")
	}
	hdr := c.snapshots("header_only")
	hdr.Get(types.Hash{2})
	hdr.Get(types.Hash{3})
	c.snapshots("").Get(types.Hash{4})

	got := map[string]float64{}
	for _, f := range reg.Gather() {
		for _, s := range f.Samples {
			got[s.Labels["context"]] = s.Value
		}
	}
	if len(got) != 2 || got["preprepare"] != 1 || got["header_only"] != 2 {
		t.Fatalf("misses %v", got)
	}
}

// TestBuildCacheMiss counts a parent snapshot that the proposal builder
// fetches from the application, and not one it finds in the cache.
func TestBuildCacheMiss(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key})
	if err != nil {
		t.Fatal(err)
	}
	head := codec.BlockHash(a.Head())
	for range 2 {
		if _, err := n.svc.snapshot(context.Background(), head); err != nil {
			t.Fatal(err)
		}
	}
	var got float64
	for _, f := range n.Metrics().Gather() {
		if f.Name == "wbft_authority_cache_misses_total" {
			for _, s := range f.Samples {
				if s.Labels["context"] == "build" {
					got += s.Value
				}
			}
		}
	}
	if got != 1 {
		t.Fatalf("build misses %v", got)
	}
}

// TestSnapshotMissingHealth: a node whose application passes every snapshot
// reports no missing one; a head announced without its snapshot is
// reported (snapshot_missing_at_head), and so is a PRE-PREPARE whose
// parent snapshot the cache does not hold (snapshot_missing_at_preprepare).
func TestSnapshotMissingHealth(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	ev := &syncBuffer{}
	n := startNode(t, a, fsys.NewMem(), key, false, ev)
	a.waitHead(t, 3, 20*time.Second)
	if strings.Contains(ev.String(), "snapshot_missing") {
		t.Fatalf("a snapshot missing with an orderly application:\n%.2000s", ev.String())
	}
	a.noSnapshot.Store(true)
	h := a.Head().Number.RefLow64() //wbft:low64 HH-60
	a.waitHead(t, h+1, 20*time.Second)
	// The node's chain view with a cache that lacks block 1's snapshot.
	v := *n.view
	v.snaps = source.NewCache(4)
	if _, err := v.ValidateProposal(a.block(2)); !errors.Is(err, header.ErrSnapshotMissing) {
		t.Fatalf("validation without the parent snapshot: %v", err)
	}
	stop(t, n)
	out := ev.String()
	if !strings.Contains(out, `"what":"snapshot_missing_at_head"`) {
		t.Fatalf("no snapshot_missing_at_head:\n%.2000s", out)
	}
	if strings.Count(out, `"what":"snapshot_missing_at_preprepare"`) != 1 || !strings.Contains(out, `"h":"2"`) {
		t.Fatalf("no snapshot_missing_at_preprepare:\n%.2000s", out)
	}
}
