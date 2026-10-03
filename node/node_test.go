package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/rpc"
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
		{"consensus rule", func(r *app.InfoResponse) {
			var m map[string]any
			if err := json.Unmarshal(r.ChainConfigJSON, &m); err != nil {
				t.Fatal(err)
			}
			m["wbftRules"] = map[string]any{"consensusRules": map[string]any{"rejectNumberJump": 10}}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			r.ChainConfigJSON = raw
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

// TestRPC serves the wbft namespace of a running validator.
func TestRPC(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	a.appImps = []string{"app_rule"}
	ev := &syncBuffer{}
	n := startNode(t, a, fsys.NewMem(), key, false, ev)
	defer stop(t, n)
	a.waitHead(t, 1, 20*time.Second)
	srv := httptest.NewServer(rpc.Handler(n.APIs()))
	defer srv.Close()
	call := func(method string) map[string]any {
		resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	info := call("wbft_nodeInfo")["result"].(map[string]any)
	if info["impl"] != "wbft" || info["validator"] != true || info["address"] != strings.ToLower(n.Address().Hex()) {
		t.Fatalf("nodeInfo %v", info)
	}
	// The mode, the BLS key (48 bytes), the build and the improvements with
	// their source: the core's restart-safety rules, then the app's.
	imps, _ := json.Marshal(info["improvements"])
	want := `[{"name":"one_round0_proposal","source":"profile"},{"name":"bad_block_release_mark","source":"profile"},` +
		`{"name":"app_rule","source":"app"}]`
	if info["mode"] != "embedded" || len(info["blsPublicKey"].(string)) != 2+96 || info["build"] != "cgo" ||
		info["version"] == "" || string(imps) != want {
		t.Fatalf("nodeInfo %v", info)
	}
	if s := ev.String(); !strings.Contains(s, `"kind":"NODE_START"`) || !strings.Contains(s, `"mode":"embedded"`) ||
		!strings.Contains(s, `"improvements":`+want) {
		t.Fatalf("NODE_START: %s", s[:min(len(s), 600)])
	}
	// An EVIDENCE record of the core goes through the node's sink to the
	// store and the event stream, and wbft_evidence returns it.
	sink := &evidenceSink{store: n.evid, next: n.ev, log: n.log}
	if err := sink.Write(event.Record{Kind: event.Evidence, View: &event.View{Seq: "7", Round: "1"}, Fields: map[string]any{
		"code": uint64(2), "evidence_kind": "equivocation", "source": "0x01", "digest_a": "0xaa", "digest_b": "0xbb",
		"sig_a": "0x11", "sig_b": "0x22"}}, event.Stamp{Wall: time.Unix(1_700_000_000, 0)}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_evidence","params":["5","0x9"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var evOut struct{ Result []map[string]any }
	if err := json.NewDecoder(resp.Body).Decode(&evOut); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(evOut.Result) != 1 || evOut.Result[0]["height"] != "7" || evOut.Result[0]["digestB"] != "0xbb" ||
		evOut.Result[0]["code"] != float64(2) || !strings.Contains(ev.String(), `"kind":"EVIDENCE"`) {
		t.Fatalf("wbft_evidence %+v", evOut.Result)
	}
	if st := call("wbft_consensusState")["result"].(map[string]any); st["running"] != true {
		t.Fatalf("consensusState %v", st)
	}
	if e := call("wbft_nope")["error"]; e == nil {
		t.Fatal("unknown method answered")
	}
}

// TestVerifyEpochInfoNonEpoch: a block that is not an epoch block passes
// without EpochInfo and fails with one.
func TestVerifyEpochInfoNonEpoch(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	defer stop(t, n)
	h := g.Header.Copy()
	h.Number = types.HeightFromUint64(1)
	if err := codec.SetExtra(h, &types.WBFTExtra{}); err != nil {
		t.Fatal(err)
	}
	if err := n.Consensus().VerifyEpochInfo(context.Background(), h); err != nil {
		t.Fatalf("non-epoch block without EpochInfo: %v", err)
	}
	if err := codec.SetExtra(h, &types.WBFTExtra{EpochInfo: &types.EpochInfo{}}); err != nil {
		t.Fatal(err)
	}
	if err := n.Consensus().VerifyEpochInfo(context.Background(), h); !errors.Is(err, epoch.ErrEpochInfoIsNotNil) {
		t.Fatalf("non-epoch block with EpochInfo: %v", err)
	}
}

// nativeAuthority marks the test application's authority as native.
type nativeAuthority struct{ *testApp }

func (nativeAuthority) NativeAuthority() {}

// TestNativeAuthorityMode refuses a native authority source in embedded
// mode and accepts it in standalone mode.
func TestNativeAuthorityMode(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	d := Deps{App: a, Authority: nativeAuthority{a}, fs: fsys.NewMem(), key: key}
	if _, err := New(Config{DataDir: "/data"}, d); !errors.Is(err, ErrConfig) {
		t.Fatalf("embedded mode with a native source: %v", err)
	}
	sn, err := New(Config{DataDir: "/data", Standalone: true}, d)
	if err != nil {
		t.Fatalf("standalone mode: %v", err)
	}
	if m := (backend{sn}).NodeInfo().Mode; m != "standalone" {
		t.Fatalf("nodeInfo mode %q", m)
	}
	if _, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), key: key}); err != nil {
		t.Fatalf("embedded mode with a plain source: %v", err)
	}
}

// TestRejections records the two sources of rejections and serves them
// through wbft_rejections: a proposal that fails the proposal checks (path
// preprepare; an unknown parent fails V0b) and an import failure the application reports (its path,
// step and class). The IMPORT_FAIL event carries the step as failed_step
// and reaches the event stream.
func TestRejections(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	ev := &syncBuffer{}
	n := startNode(t, a, fsys.NewMem(), key, false, ev)
	defer stop(t, n)
	a.waitHead(t, 1, 20*time.Second)
	bad := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(500), Difficulty: big.NewInt(1)}}
	if _, err := n.view.ValidateProposal(bad); err == nil {
		t.Fatal("a bad proposal passed")
	}
	n.Consensus().OnImportFailed(app.ImportFailure{Number: types.HeightFromUint64(501), Hash: types.Hash{1}, Path: app.Imported,
		Err: &app.ImportError{Step: "H5", Class: "ErrInvalidMixDigest"}})
	if s := ev.String(); !strings.Contains(s, `"kind":"IMPORT_FAIL"`) || !strings.Contains(s, `"failed_step":"H5"`) ||
		!strings.Contains(s, `"error_class":"ErrInvalidMixDigest"`) {
		t.Fatalf("IMPORT_FAIL not in the event stream")
	}
	srv := httptest.NewServer(rpc.Handler(n.APIs()))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_rejections","params":[500,"0x1f5"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Result []map[string]any }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	r := out.Result
	if len(r) != 2 || r[0]["number"] != "500" || r[0]["path"] != "preprepare" || r[0]["step"] != "V0b" || r[0]["errorClass"] != "ErrUnknownAncestor" ||
		r[1]["number"] != "501" || r[1]["path"] != "imported" || r[1]["step"] != "H5" || r[1]["errorClass"] != "ErrInvalidMixDigest" {
		t.Fatalf("wbft_rejections %+v", r)
	}
}

// TestHeaderCopy returns this node's copy of a header it decided: round 0,
// the committed seal of the single validator (index 0) and the path
// sealed_locally; a header the node never saw as a head has the path
// unknown, and one it does not hold is null.
func TestHeaderCopy(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	defer stop(t, n)
	a.waitHead(t, 2, 20*time.Second)
	srv := httptest.NewServer(rpc.Handler(n.APIs()))
	defer srv.Close()
	call := func(hash types.Hash) map[string]any {
		t.Helper()
		resp, err := http.Post(srv.URL, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_headerCopy","params":["`+hash.Hex()+`"]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Result map[string]any }
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Result
	}
	h := a.HeaderByNumber(1)
	c := call(codec.BlockHash(h))
	cs, _ := c["committedSeal"].(map[string]any)
	if c["number"] != "1" || c["path"] != "sealed_locally" || c["round"] != float64(0) || cs == nil ||
		fmt.Sprint(cs["sealers"]) != "[0]" || len(cs["signature"].(string)) != 2+192 {
		t.Fatalf("wbft_headerCopy(1) %v", c)
	}
	if c := call(codec.BlockHash(g.Header)); c["path"] != "unknown" {
		t.Fatalf("the genesis copy %v", c)
	}
	if c := call(types.Hash{9}); c != nil {
		t.Fatalf("an unknown header %v", c)
	}
}
