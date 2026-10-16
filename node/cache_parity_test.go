package node

import (
	"bytes"
	"crypto/sha256"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
	"testing"
	"time"
)

type cacheObservationClock struct{}

func (cacheObservationClock) Now() time.Time      { return time.Unix(1000, 0) }
func (cacheObservationClock) Mono() time.Duration { return 5 * time.Second }
func (cacheObservationClock) AfterFunc(d time.Duration, f func()) runner.Timer {
	return time.AfterFunc(d, f)
}

type cacheIsolatedTransport struct{}

func (cacheIsolatedTransport) Send(peers []types.Address, _ uint64, _ []byte) []transport.SendResult {
	r := make([]transport.SendResult, len(peers))
	for i := range r {
		r[i] = transport.NotAttached
	}
	return r
}
func (cacheIsolatedTransport) SetReceiver(transport.Receiver)         {}
func (cacheIsolatedTransport) PeerEvents() <-chan transport.PeerEvent { return nil }
func (cacheIsolatedTransport) Peers() []transport.PeerInfo            { return nil }
func (cacheIsolatedTransport) Disconnect(types.Address, string)       {}

// This bounded node pair exercises real Dedup mutations with no remote peers.
// Queue/wire parity is tested separately in the transport adapter tests.
func TestCacheObservationPreservesSignedBlockAndState(t *testing.T) {
	var previousBlock, previousState []byte
	var previousOwn [][]byte
	for _, enabled := range []bool{false, true} {
		key := testKey(0)
		cfg, g := testGenesis(t, key)
		g.Header.Time = 999
		a := newTestApp(cfg, g)
		mem := fsys.NewMem()
		config := Config{DataDir: "/data", RunID: "cache-parity"}
		config.Journal.Disabled = !enabled
		n, err := New(config, Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: mem, key: key, clock: cacheObservationClock{}})
		if err != nil {
			t.Fatal(err)
		}
		a.cons = n.Consensus()
		if err = n.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.waitHead(t, 1, 5*time.Second)
		if err = n.Stop(); err != nil {
			t.Fatal(err)
		}
		if a.Head().Number.CmpUint64(1) != 0 {
			t.Fatal("bounded block target changed")
		}
		a.mu.Lock()
		block := a.byNum[1]
		a.mu.Unlock()
		encoded, err := codec.EncodeBlock(block)
		if err != nil {
			t.Fatal(err)
		}
		state, err := mem.ReadFile("/data/privval/state")
		if err != nil {
			t.Fatal(err)
		}
		records, _, err := wal.ReadAll(mem, "/data/wal")
		if err != nil {
			t.Fatal(err)
		}
		var own [][]byte
		for _, r := range records {
			if r.Format == 1 && r.Kind == 4 {
				own = append(own, r.Body)
			}
		}
		if len(own) != 3 {
			t.Fatal("signed own-message count changed", len(own))
		}
		instances, operations := 0, 0
		if enabled {
			rows, err := journal.ReadAll(mem, "/data/journal")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if op, ok := r.Body.(*journal.CacheRec); ok {
					if op.Action == "begin" {
						instances++
					} else {
						operations++
					}
				}
			}
			if instances != 1 || operations == 0 {
				t.Fatal("actual cache observation was not exercised", instances, operations)
			}
			if !bytes.Equal(encoded, previousBlock) || !bytes.Equal(state, previousState) || len(own) != len(previousOwn) {
				t.Fatal("cache observation changed signed block or state")
			}
			for i := range own {
				if !bytes.Equal(own[i], previousOwn[i]) {
					t.Fatal("cache observation changed signed WAL bytes")
				}
			}
		} else {
			previousBlock = encoded
			previousState = state
			previousOwn = own
		}

		t.Logf("cache_pair journal=%t block_sha256=%x sign_state_sha256=%x signed_wal_records=%d cache_instances=%d cache_operations=%d", enabled, sha256.Sum256(encoded), sha256.Sum256(state), len(own), instances, operations)
	}
}
