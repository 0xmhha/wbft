package node

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/p2p/transport"
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
	mems := make([]*fsys.Mem, n)
	for i := range nodes {
		apps[i] = newTestApp(cj, g)
		mems[i] = fsys.NewMem()
		nd, err := New(Config{DataDir: "/data"}, Deps{App: apps[i], Authority: apps[i], Transport: trs[i], fs: mems[i], key: keys[i]})
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
	// Gossip left relays out for peers that held them, and the receive
	// queue size is a metric.
	var text strings.Builder
	if err := nodes[0].Metrics().WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "wbft_send_suppressed_total{cause=") || !strings.Contains(text.String(), "wbft_peer_inbound_queue_bytes ") {
		t.Fatalf("network metrics:\n%s", text.String())
	}
	// Received copies hit the known cache, and every phase of a view was
	// measured.
	for _, want := range []string{`wbft_dedup_hits_total{cache="known"}`, "wbft_consensus_state ",
		`wbft_phase_seconds_count{phase="preprepare"}`, `wbft_phase_seconds_count{phase="prepare_quorum"}`,
		`wbft_phase_seconds_count{phase="commit_quorum"}`, `wbft_phase_seconds_count{phase="commit"}`,
		`wbft_phase_seconds_count{phase="import"}`} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("no %s in the network metrics:\n%s", want, text.String())
		}
	}
	if err := nodes[0].Stop(); err != nil {
		t.Fatal(err)
	}
	checkFrameJournal(t, mems[0], addrs[1:], addrs[n-1])
}

// checkFrameJournal checks the msg and peer records of a node's journal:
// every peer was attached with its own index, the stopped peer was closed,
// messages were received and written with a cause, every msg record
// carries the dedup key of its payload, and received frames carry their
// dedup cache hits: some new, some already known (relayed copies).
func checkFrameJournal(t *testing.T, mem *fsys.Mem, peers []types.Address, stopped types.Address) {
	t.Helper()
	recs, err := journal.ReadAll(mem, "/data/journal")
	if err != nil {
		t.Fatal(err)
	}
	idx := map[uint32]types.Address{}
	closed := false
	count := map[string]int{}
	for _, r := range recs {
		switch b := r.Body.(type) {
		case *journal.PeerRec:
			if a, ok := idx[b.PeerIdx]; ok && a != b.Addr {
				t.Fatalf("peer index %d is %x and %x", b.PeerIdx, a, b.Addr)
			}
			idx[b.PeerIdx] = b.Addr
			closed = closed || (b.Event == "closed" && b.Addr == stopped)
		case *journal.MsgRec:
			if _, ok := idx[b.PeerIdx]; !ok && b.Write != transport.WriteNotAttached {
				t.Fatalf("msg record of peer %d before its peer record", b.PeerIdx)
			}
			if b.DedupKey != codec.DedupKey(b.Payload) || b.WireCode != b.Code || b.Mono <= 0 || b.WallNs <= 0 {
				t.Fatalf("msg record %+v", b)
			}
			count[b.Dir+" "+b.Offer+b.Write]++
			switch {
			case b.Dedup == nil:
			case b.Dir != journal.In || b.Offer != transport.OfferQueued:
				t.Fatalf("dedup hits on a frame the node did not check: %+v", b)
			case b.Dedup.Known:
				count["dedup known"]++
			default:
				count["dedup new"]++
			}
			if b.Dir == journal.Out {
				if b.Cause == "" {
					t.Fatalf("sent msg record without a cause: %+v", b)
				}
				count["cause "+string(b.Cause)]++
			}
		case *journal.SuppressedRec:
			count["suppressed "+string(b.Cause)]++
		}
	}
	for _, p := range peers {
		if !slices.Contains(slices.Collect(maps.Values(idx)), p) {
			t.Fatalf("no peer record of %x", p)
		}
	}
	if !closed {
		t.Fatal("no closed record of the stopped peer")
	}
	t.Logf("node 0 journal: %v", count)
	for _, k := range []string{"in queued", "out ok", "cause broadcast", "dedup new", "dedup known"} {
		if count[k] == 0 {
			t.Fatalf("no %q msg records: %v", k, count)
		}
	}
}
