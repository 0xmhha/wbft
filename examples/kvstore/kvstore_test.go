package kvstore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/types"
)

type testNet struct {
	t     *testing.T
	g     *Genesis
	vals  []Validator
	homes []string
	keys  []string
	ports []string
	nodes []*Node
}

func newTestNet(t *testing.T, n int) *testNet {
	t.Helper()
	tn := &testNet{t: t}
	dir := t.TempDir()
	for i := range n {
		home := filepath.Join(dir, fmt.Sprintf("node%d", i))
		key := filepath.Join(dir, fmt.Sprintf("key%d", i))
		v, err := NewKeyFile(key)
		if err != nil {
			t.Fatal(err)
		}
		tn.vals, tn.homes, tn.keys = append(tn.vals, v), append(tn.homes, home), append(tn.keys, key)
	}
	g, err := NewGenesis(GenesisParams{ChainID: 7, BlockPeriodSeconds: 1, RequestTimeoutSeconds: 2, EpochLength: 5,
		Time: uint64(time.Now().Unix()) - 1}, tn.vals)
	if err != nil {
		t.Fatal(err)
	}
	tn.g = g
	tn.nodes = make([]*Node, n)
	tn.ports = make([]string, n)
	for i := range n {
		tn.ports[i] = "127.0.0.1:0"
	}
	for i := range n {
		tn.open(i)
	}
	// All endpoints are known now; set the peer lists and start.
	for i := range n {
		tn.start(i)
	}
	t.Cleanup(func() {
		for _, nd := range tn.nodes {
			if nd != nil {
				_ = nd.Stop()
			}
		}
	})
	return tn
}

func (tn *testNet) open(i int) {
	nd, err := NewNode(NodeConfig{Home: tn.homes[i], Genesis: tn.g, KeyFile: tn.keys[i], Self: tn.vals[i].Address,
		Listen: tn.ports[i], Network: "kvstore-test"})
	if err != nil {
		tn.t.Fatal(err)
	}
	if err := nd.tr.Listen(); err != nil {
		tn.t.Fatal(err)
	}
	tn.ports[i] = nd.Endpoint()
	tn.nodes[i] = nd
}

func (tn *testNet) start(i int) {
	var peers []devnet.Peer
	for j, v := range tn.vals {
		if j != i {
			peers = append(peers, devnet.Peer{Addr: v.Address, Endpoint: tn.ports[j]})
		}
	}
	tn.nodes[i].tr.SetPeers(peers)
	if err := tn.nodes[i].Start(context.Background()); err != nil {
		tn.t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func submit(t *testing.T, nd *Node, tx Tx) {
	t.Helper()
	raw, err := tx.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r, err := nd.Node.Mempool().Add(context.Background(), raw)
	if err != nil || r.Code != mempool.CodeOK {
		t.Fatalf("add %+v: %v %v", tx, r, err)
	}
}

func height(nd *Node) uint64 { return nd.App.Head().Number.RefLow64() } //wbft:low64 HH-60

// TestNetwork runs four kvstore validators: transactions submitted to one
// node reach every state, the chain crosses epoch blocks, a stopped node
// catches up after its restart, and all nodes store the same blocks.
func TestNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	tn := newTestNet(t, 4)
	alice := types.Address{0xa1}
	for i := range uint64(3) {
		submit(t, tn.nodes[0], Tx{From: alice, Nonce: i, Key: "k", Value: fmt.Sprint(i)})
	}
	for i, nd := range tn.nodes {
		waitFor(t, fmt.Sprintf("node %d state", i), 60*time.Second, func() bool {
			v, _ := nd.App.Get("k")
			return v == "2" && nd.App.Nonce(alice) == 3
		})
	}

	// Stop node 3; the others continue past an epoch block.
	if err := tn.nodes[3].Stop(); err != nil {
		t.Fatal(err)
	}
	tn.nodes[3] = nil
	target := height(tn.nodes[0]) + 6
	waitFor(t, "progress without node 3", 60*time.Second, func() bool { return height(tn.nodes[0]) >= target })
	submit(t, tn.nodes[1], Tx{From: alice, Nonce: 3, Key: "k", Value: "3"})

	// Restart node 3 on its data and endpoint (the peers keep dialing the
	// endpoint they know); it catches up.
	tn.open(3)
	tn.start(3)
	waitFor(t, "node 3 catches up", 60*time.Second, func() bool {
		v, _ := tn.nodes[3].App.Get("k")
		return v == "3" && height(tn.nodes[3]) >= target
	})

	// Agreement on every stored block.
	for n := uint64(1); n <= height(tn.nodes[3]); n++ {
		want := tn.nodes[0].App.BlockByNumber(n)
		for i, nd := range tn.nodes {
			if b := nd.App.BlockByNumber(n); b != nil && want != nil && codec.BlockHash(b.Header) != codec.BlockHash(want.Header) {
				t.Fatalf("node %d: block %d differs", i, n)
			}
		}
	}
}

// TestReopen rebuilds the state from the stored blocks.
func TestReopen(t *testing.T) {
	dir := t.TempDir()
	v, err := NewKeyFile(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGenesis(GenesisParams{ChainID: 7, BlockPeriodSeconds: 1, RequestTimeoutSeconds: 2, EpochLength: 100,
		Time: uint64(time.Now().Unix()) - 1}, []Validator{v})
	if err != nil {
		t.Fatal(err)
	}
	cfg := NodeConfig{Home: filepath.Join(dir, "home"), Genesis: g, KeyFile: filepath.Join(dir, "key"), Self: v.Address}
	nd, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := nd.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	bob := types.Address{0xb0}
	submit(t, nd, Tx{From: bob, Nonce: 0, Key: "a", Value: "1"})
	waitFor(t, "inclusion", 30*time.Second, func() bool { return nd.App.Nonce(bob) == 1 })
	if err := nd.Stop(); err != nil {
		t.Fatal(err)
	}
	a, err := Open(filepath.Join(cfg.Home, "app"), g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := a.Get("a"); !ok || v != "1" || a.Nonce(bob) != 1 {
		t.Fatalf("reopened state: %q %v nonce %d", v, ok, a.Nonce(bob))
	}
	// A transaction with a used nonce is refused.
	nd, err = NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := nd.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := nd.Stop(); err != nil {
			t.Error(err)
		}
	}()
	raw, _ := Tx{From: bob, Nonce: 0, Key: "a", Value: "2"}.Encode()
	if r, err := nd.Node.Mempool().Add(context.Background(), raw); err != nil || r.Code != mempool.CodeReject {
		t.Fatalf("reused nonce: %v %v", r, err)
	}
}
