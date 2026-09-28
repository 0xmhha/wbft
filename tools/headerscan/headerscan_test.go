package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestScanRanges(t *testing.T) {
	for _, tt := range []struct {
		name  string
		forks []uint64
		span  uint64
		head  uint64
		want  []blockRange
	}{
		{"testnet", []uint64{0, 14_408_500}, 100, 20_000_000, []blockRange{{0, 100}, {14_408_500, 14_408_600}}},
		{"fork at 0 only", []uint64{0, 0}, 100, 1000, []blockRange{{0, 100}}},
		{"overlap merged", []uint64{50, 120}, 100, 1000, []blockRange{{0, 220}}},
		{"touching merged", []uint64{101}, 100, 1000, []blockRange{{0, 201}}},
		{"unsorted forks", []uint64{900, 400}, 10, 1000, []blockRange{{0, 10}, {400, 410}, {900, 910}}},
		{"clipped to head", []uint64{95}, 100, 120, []blockRange{{0, 120}}},
		{"fork after head", []uint64{500}, 100, 120, []blockRange{{0, 100}}},
		{"overflow", []uint64{^uint64(0) - 5}, 100, ^uint64(0), []blockRange{{0, 100}, {^uint64(0) - 5, ^uint64(0)}}},
	} {
		if got := scanRanges(tt.forks, tt.span, tt.head); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseForks(t *testing.T) {
	got, err := parseForks("0, 14_408_500,,7")
	if err != nil || !slices.Equal(got, []uint64{0, 14408500, 7}) {
		t.Errorf("parseForks = %v %v", got, err)
	}
	if _, err := parseForks("x"); err == nil {
		t.Error("bad fork block accepted")
	}
}

// The limiter spaces requests by its interval and does not sleep when the
// caller is already late.
func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	var slept []time.Duration
	l := newLimiter(200 * time.Millisecond)
	l.now = func() time.Time { return now }
	l.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}
	ctx := context.Background()
	for range 3 {
		if err := l.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Second)
	if err := l.wait(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{200 * time.Millisecond, 200 * time.Millisecond}; !slices.Equal(slept, want) {
		t.Errorf("slept %v, want %v", slept, want)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	l.sleep = sleepCtx
	if err := l.wait(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait: %v", err)
	}
}

// sampleHeader is a header with every field set, as a node would report it.
func sampleHeader() (*types.Header, rpcHeader) {
	wh, pbr := types.Hash{0x0a}, types.Hash{0x0b}
	blob, excess := uint64(0x20000), uint64(3)
	h := &types.Header{
		ParentHash: types.Hash{1}, UncleHash: types.EmptyUncleHash, Coinbase: types.Address{2}, Root: types.Hash{3},
		TxHash: types.Hash{4}, ReceiptHash: types.Hash{5}, Difficulty: big.NewInt(1), Number: types.HeightFromUint64(300),
		GasLimit: 105_000_000, GasUsed: 21000, Time: 1_700_000_300, Extra: []byte{0xc0},
		MixDigest: types.Hash{6}, Nonce: types.Nonce{7}, BaseFee: big.NewInt(20_000_000_000_000),
		WithdrawalsHash: &wh, BlobGasUsed: &blob, ExcessBlobGas: &excess, ParentBeaconRoot: &pbr,
	}
	h.Bloom[255] = 8
	hex := func(b []byte) string { return "0x" + encodeHex(b) }
	str := func(s string) *string { return &s }
	r := rpcHeader{
		Hash: codec.BlockHash(h).Hex(), ParentHash: hex(h.ParentHash[:]), UncleHash: hex(h.UncleHash[:]),
		Coinbase: hex(h.Coinbase[:]), Root: hex(h.Root[:]), TxHash: hex(h.TxHash[:]), ReceiptHash: hex(h.ReceiptHash[:]),
		Bloom: hex(h.Bloom[:]), Difficulty: "0x1", Number: "0x12c", GasLimit: "0x6422c40", GasUsed: "0x5208",
		Time: "0x6553f22c", Extra: "0xc0", MixDigest: hex(h.MixDigest[:]), Nonce: hex(h.Nonce[:]),
		BaseFee: str("0x12309ce54000"), WithdrawalsHash: str(hex(wh[:])), BlobGasUsed: str("0x20000"),
		ExcessBlobGas: str("0x3"), ParentBeaconRoot: str(hex(pbr[:])),
	}
	return h, r
}

func encodeHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

func TestToHeader(t *testing.T) {
	want, r := sampleHeader()
	got, reported, err := r.toHeader()
	if err != nil {
		t.Fatal(err)
	}
	if reported != codec.BlockHash(want) || codec.BlockHash(got) != reported {
		t.Errorf("hash %s, computed %s, want %s", reported.Hex(), codec.BlockHash(got).Hex(), codec.BlockHash(want).Hex())
	}
	if codec.HeaderHash(got) != codec.HeaderHash(want) {
		t.Error("the converted header encodes differently")
	}
	// Optional fields stay absent when the node does not report them.
	r.BaseFee, r.WithdrawalsHash, r.BlobGasUsed, r.ExcessBlobGas, r.ParentBeaconRoot = nil, nil, nil, nil, nil
	got, _, err = r.toHeader()
	if err != nil || got.BaseFee != nil || got.WithdrawalsHash != nil || got.BlobGasUsed != nil || got.ExcessBlobGas != nil || got.ParentBeaconRoot != nil {
		t.Errorf("absent optional fields: %+v %v", got, err)
	}
	for name, mut := range map[string]func(r *rpcHeader){
		"short hash":    func(r *rpcHeader) { r.ParentHash = r.ParentHash[:10] },
		"no 0x":         func(r *rpcHeader) { r.Root = strings.TrimPrefix(r.Root, "0x") },
		"bad number":    func(r *rpcHeader) { r.Number = "0x" },
		"bad gas limit": func(r *rpcHeader) { r.GasLimit = "0x1ffffffffffffffff" },
		"bad extra":     func(r *rpcHeader) { r.Extra = "0xz0" },
	} {
		_, r := sampleHeader()
		mut(&r)
		if _, _, err := r.toHeader(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeNode answers eth_getBlockByNumber from a map and counts requests.
func fakeNode(t *testing.T, blocks map[string]any) (*httptest.Server, *int) {
	t.Helper()
	n := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		*n++
		body, _ := io.ReadAll(req.Body)
		var call struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.Unmarshal(body, &call); err != nil {
			t.Errorf("request %s: %v", body, err)
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": call.ID}
		switch call.Method {
		case "eth_chainId":
			resp["result"] = "0x205b"
		case "eth_getBlockByNumber":
			resp["result"] = blocks[call.Params[0].(string)]
		default:
			resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, n
}

func TestClient(t *testing.T) {
	want, r := sampleHeader()
	srv, requests := fakeNode(t, map[string]any{"0x12c": r, "0x12d": nil})
	c := newClient(srv.URL, newLimiter(time.Millisecond))
	ctx := context.Background()
	id, err := c.chainID(ctx)
	if err != nil || id.Int64() != 8283 {
		t.Errorf("chain id %v %v", id, err)
	}
	h, hash, err := c.headerByNumber(ctx, 300)
	if err != nil || hash != codec.BlockHash(want) || h.Time != want.Time {
		t.Errorf("header 300: %v %v", hash.Hex(), err)
	}
	if _, _, err := c.headerByNumber(ctx, 301); !errors.Is(err, errNotFound) {
		t.Errorf("missing block: %v", err)
	}
	// An error answer is not retried.
	before := *requests
	var rerr *rpcError
	if _, err := c.blockNumber(ctx); !errors.As(err, &rerr) || *requests != before+1 {
		t.Errorf("rpc error: %v after %d requests", err, *requests-before)
	}
	if c.requests != *requests {
		t.Errorf("client counted %d requests, server saw %d", c.requests, *requests)
	}
}

// staticSource serves fixed headers with the hashes a node would report.
type staticSource map[uint64]struct {
	h        *types.Header
	reported types.Hash
}

func (s staticSource) headerByNumber(_ context.Context, n uint64) (*types.Header, types.Hash, error) {
	x, ok := s[n]
	if !ok {
		return nil, types.Hash{}, errNotFound
	}
	return x.h, x.reported, nil
}

func (s staticSource) headerByHash(ctx context.Context, hash types.Hash) (*types.Header, types.Hash, error) {
	for n, x := range s {
		if x.reported == hash {
			return s.headerByNumber(ctx, n)
		}
	}
	return nil, types.Hash{}, errNotFound
}

// A header whose computed hash differs from the reported one stops the
// scan instead of being verified against wrong links.
func TestRPCChainHashCheck(t *testing.T) {
	h, _ := sampleHeader()
	good := codec.BlockHash(h)
	src := staticSource{300: {h, good}, 301: {h, types.Hash{9}}}
	c := newRPCChain(context.Background(), src)
	if got := c.HeaderByNumber(300); got != h || c.err != nil {
		t.Fatalf("good header: %v %v", got, c.err)
	}
	if c.Header(good, 300) != h || c.HeaderByHash(good) != h || c.Head() != h {
		t.Error("lookups of the stored header")
	}
	if c.HeaderByNumber(302) != nil || c.err != nil {
		t.Errorf("missing header: %v", c.err)
	}
	var mismatch *hashMismatchError
	if c.HeaderByNumber(301) != nil || !errors.As(c.err, &mismatch) {
		t.Errorf("mismatch: %v", c.err)
	}
}

func TestRunFlags(t *testing.T) {
	var out, errOut strings.Builder
	if code := run(context.Background(), []string{"-rate", "10"}, &out, &errOut); code != 2 {
		t.Errorf("-rate 10: exit %d", code)
	}
	if code := run(context.Background(), []string{"-forks", "x"}, &out, &errOut); code != 2 {
		t.Errorf("-forks x: exit %d", code)
	}
}

// The built-in preset parses and names the testnet.
func TestTestnetPreset(t *testing.T) {
	cfg, err := types.ParseChainConfig([]byte(testnetPreset.config))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChainID.Int64() != 8283 || len(cfg.Init.Validators) != 7 || cfg.Base().EpochLength != 140 || cfg.CheckProposerPolicy() != nil {
		t.Errorf("preset %+v", cfg.Base())
	}
	if err := cfg.Init.Check(); err != nil {
		t.Error(err)
	}
	if !slices.Contains(testnetPreset.forks, 14_408_500) {
		t.Error("Boho block missing")
	}
}
