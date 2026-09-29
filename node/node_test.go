package node

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/types"
)

// startNode starts a node for the key on fs with the test application a.
func startNode(t *testing.T, a *testApp, fs fsys.FS, key []byte, guard bool, ev *syncBuffer) *Node {
	t.Helper()
	d := Deps{App: a, Authority: a, fs: fs, key: key}
	if ev != nil {
		d.Events = ev
	}
	n, err := New(Config{DataDir: "/data", TakeoverGuard: guard}, d)
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSingleValidatorChain runs one validator that builds and decides
// blocks through the application interface.
func TestSingleValidatorChain(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	ev := &syncBuffer{}
	n := startNode(t, a, fsys.NewMem(), key, false, ev)
	a.waitHead(t, 3, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev.String(), `"kind":"SEND"`) {
		t.Fatal("no SEND record")
	}
	// Notifications after Stop are dropped and calls return ErrStopped.
	a.cons.OnNewHead(app.NewHead{Header: a.Head()})
	if _, err := a.cons.PrepareConsensusFields(context.Background(), &types.Header{}); !errors.Is(err, app.ErrStopped) {
		t.Fatalf("after Stop: %v", err)
	}
}

// TestRestartContinues stops a validator and starts it again on the same
// state: it continues from the head.
func TestRestartContinues(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	fs := fsys.NewMem()
	n := startNode(t, a, fs, key, true, nil)
	a.waitHead(t, 2, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	head := a.Head().Number.RefLow64() //wbft:low64 HH-60
	n = startNode(t, a, fs, key, true, nil)
	defer stop(t, n)
	a.waitHead(t, head+2, 20*time.Second)
}

// TestSignFloorNode is the node-level test of the sign floor of a
// taken-over key (TakeoverGuard):
//
//   - at H_app = 0 no floor is set;
//   - a sign state that holds a signature gets no new floor;
//   - an empty sign state with H_app >= 1 gets the floor H_app + 1, and the
//     node signs nothing at H_app + 1.
func TestSignFloorNode(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)

	t.Run("genesis head", func(t *testing.T) {
		a := newTestApp(cj, g)
		n := startNode(t, a, fsys.NewMem(), key, true, nil)
		defer stop(t, n)
		if f, ok := n.SignFloor(); ok {
			t.Fatalf("floor %s at H_app = 0", f)
		}
		a.waitHead(t, 1, 20*time.Second)
	})

	a := newTestApp(cj, g)
	fs := fsys.NewMem()
	n := startNode(t, a, fs, key, true, nil)
	a.waitHead(t, 2, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}

	t.Run("sign record kept", func(t *testing.T) {
		n := startNode(t, a, fs, key, true, nil)
		defer stop(t, n)
		if f, ok := n.SignFloor(); ok {
			t.Fatalf("floor %s over an existing sign record", f)
		}
	})

	t.Run("taken-over key", func(t *testing.T) {
		// The same key on a new data directory: the sign state is empty.
		checkTakeover(t, a, fsys.NewMem(), key)
	})
}

// checkTakeover starts a node with an empty sign state on the chain of a,
// and requires the floor at head + 1 and no signature at head + 1.
func checkTakeover(t *testing.T, a *testApp, fs fsys.FS, key []byte) {
	t.Helper()
	ev := &syncBuffer{}
	head := a.Head().Number
	n := startNode(t, a, fs, key, true, ev)
	defer stop(t, n)
	f, ok := n.SignFloor()
	if !ok || f.Cmp(head.AddUint64(1)) != 0 {
		t.Fatalf("floor %v %v, want %s", f, ok, head.AddUint64(1))
	}
	// The single validator is the proposer of head + 1; it refuses to sign
	// there, so the chain stays at head.
	waitEvent(t, ev, `"what":"sign_floor_skip"`, 20*time.Second)
	if a.Head().Number.Cmp(head) != 0 {
		t.Fatalf("head moved to %s over the floor", a.Head().Number)
	}
	// The node works only at head + 1 and has no peers, so any SEND record
	// would be an own signed message at head + 1 (a node without a floor
	// writes SEND records, see TestSingleValidatorChain).
	if strings.Contains(ev.String(), `"kind":"SEND"`) {
		t.Fatal("sent a signed message at the floor height")
	}
}

// TestStartChecks covers the start-up checks.
func TestStartChecks(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	cases := []struct {
		name string
		info func(*app.InfoResponse)
	}{
		{"interface version", func(r *app.InfoResponse) { r.AppMajors = []uint32{app.Major + 1} }},
		{"genesis hash", func(r *app.InfoResponse) { r.GenesisHash = types.Hash{1} }},
		{"no proposer policy", func(r *app.InfoResponse) {
			r.ChainConfigJSON = []byte(`{"chainId":8282,"anzeon":{"wbft":{"blockPeriodSeconds":1},"init":{"validators":[]}}}`)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &infoApp{newTestApp(cj, g), c.info}
			n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key})
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Start(context.Background()); !errors.Is(err, ErrStartRefused) {
				t.Fatalf("start: %v", err)
			}
		})
	}
	if _, err := New(Config{}, Deps{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New without deps: %v", err)
	}
}

// infoApp changes the Info of a test application.
type infoApp struct {
	*testApp
	change func(*app.InfoResponse)
}

func (a *infoApp) Info(ctx context.Context) (app.InfoResponse, error) {
	r, err := a.testApp.Info(ctx)
	a.change(&r)
	return r, err
}

func stop(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Stop(); err != nil {
		t.Error(err)
	}
}

// okHook admits every transaction; the first byte is the nonce.
type okHook struct{}

func (okHook) TxKey(tx []byte) (types.Hash, error) { return keccak.Sum256(tx), nil }
func (okHook) CheckTx(_ context.Context, req mempool.CheckRequest) mempool.CheckResponse {
	return mempool.CheckResponse{Code: mempool.CodeOK, Meta: mempool.TxMeta{Nonce: uint64(req.Tx[0])}}
}

// TestMempool starts the pool with the node, and refuses an unknown
// ordering policy.
func TestMempool(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, Admission: okHook{}, fs: fsys.NewMem()})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, err := n.Mempool().Add(context.Background(), []byte{0}); err != nil || r.Code != mempool.CodeOK {
		t.Fatalf("add: %v %v", r, err)
	}
	stop(t, n)

	n, err = New(Config{DataDir: "/data", Mempool: MempoolConfig{Ordering: "stablenet"}},
		Deps{App: a, Authority: a, Admission: okHook{}, fs: fsys.NewMem()})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); !errors.Is(err, ErrStartRefused) {
		t.Fatalf("unknown ordering: %v", err)
	}
}
