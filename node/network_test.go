package node

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/types"
)

// TestFourValidators runs four validators connected by the development
// transport. They agree on every block, and the chain continues with one
// validator stopped (three of four are a quorum).
func TestFourValidators(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	const n = 4
	keys := make([][]byte, n)
	addrs := make([]types.Address, n)
	for i := range keys {
		keys[i] = testKey(i)
		pk, err := ecdsa.PrivateKeyFromBytes(keys[i])
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = ecdsa.Address(pk)
	}
	cj, g := testGenesis(t, keys...)

	trs := make([]*devnet.Transport, n)
	for i := range trs {
		tr, err := devnet.New(devnet.Config{Self: addrs[i], Listen: "127.0.0.1:0", Network: "node-test",
			RedialInterval: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Listen(); err != nil {
			t.Fatal(err)
		}
		trs[i] = tr
	}
	for i, tr := range trs {
		var peers []devnet.Peer
		for j := range trs {
			if j != i {
				peers = append(peers, devnet.Peer{Addr: addrs[j], Endpoint: trs[j].Endpoint()})
			}
		}
		tr.SetPeers(peers)
	}

	apps := make([]*testApp, n)
	nodes := make([]*Node, n)
	for i := range nodes {
		apps[i] = newTestApp(cj, g)
		nd, err := New(Config{DataDir: "/data"}, Deps{App: apps[i], Authority: apps[i], Transport: trs[i], fs: fsys.NewMem(), key: keys[i]})
		if err != nil {
			t.Fatal(err)
		}
		apps[i].cons = nd.Consensus()
		if err := nd.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		nodes[i] = nd
	}
	for _, tr := range trs {
		if err := tr.Start(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for i := range nodes {
			_ = nodes[i].Stop()
			_ = trs[i].Close()
		}
	})

	for _, a := range apps {
		a.waitHead(t, 3, 60*time.Second)
	}
	// Stop the last validator; the other three continue.
	if err := nodes[n-1].Stop(); err != nil {
		t.Fatal(err)
	}
	_ = trs[n-1].Close()
	h := apps[0].Head().Number.RefLow64() //wbft:low64 HH-60
	for _, a := range apps[:n-1] {
		a.waitHead(t, h+3, 60*time.Second)
	}
	// Agreement: the same block at every height all nodes stored.
	for num := uint64(1); num <= h; num++ {
		want := codec.BlockHash(apps[0].HeaderByNumber(num))
		for i, a := range apps {
			if hd := a.HeaderByNumber(num); hd != nil && codec.BlockHash(hd) != want {
				t.Fatalf("node %d: block %d differs", i, num)
			}
		}
	}
}
