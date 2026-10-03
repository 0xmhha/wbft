package node

import (
	"testing"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/types"
)

// TestHeadPaths keeps the most recent paths, drops the oldest beyond its
// capacity and updates a path given again.
func TestHeadPaths(t *testing.T) {
	p := newHeadPaths(2)
	p.put(types.Hash{1}, app.Imported)
	p.put(types.Hash{2}, app.Synced)
	p.put(types.Hash{2}, app.SealedLocally) // updated, not a new entry
	p.put(types.Hash{3}, app.Imported)      // drops 1
	if _, ok := p.get(types.Hash{1}); ok {
		t.Fatal("the oldest path kept")
	}
	if got, ok := p.get(types.Hash{2}); !ok || got != app.SealedLocally {
		t.Fatalf("hash 2: %v %v", got, ok)
	}
	if got, ok := p.get(types.Hash{3}); !ok || got != app.Imported {
		t.Fatalf("hash 3: %v %v", got, ok)
	}
}
