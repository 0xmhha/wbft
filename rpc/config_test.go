package rpc

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/evidence"
	"github.com/0xmhha/wbft/observe/rejection"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type fakeBackend struct{ cfg *types.Config }

func (f fakeBackend) NodeInfo() NodeInfo                               { return NodeInfo{} }
func (f fakeBackend) ConsensusState() *consensus.Snapshot              { return nil }
func (f fakeBackend) Peers() []transport.PeerInfo                      { return nil }
func (f fakeBackend) ChainConfig() *types.Config                       { return f.cfg }
func (f fakeBackend) HeaderCopy(types.Hash) (*HeaderCopyResult, error) { return nil, nil }
func (f fakeBackend) Events(uint64, int) []json.RawMessage             { return nil }
func (f fakeBackend) Chain() types.ChainReader                         { return nil }
func (f fakeBackend) Rejections(from, to *big.Int) ([]rejection.Record, error) {
	return []rejection.Record{{Number: to.String()}}, nil
}
func (f fakeBackend) Evidence(from, to *big.Int) ([]evidence.Record, error) {
	return []evidence.Record{{Height: from.String()}}, nil
}

// TestConfigAt answers config_at(h) with the transitions that make it: a
// transition at block 10 changes the epoch and the proposer policy from
// height 10 on; one without a block never applies; a height beyond 64 bits
// is read in full.
func TestConfigAt(t *testing.T) {
	sticky := uint64(1)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 5},
		[]types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{EpochLength: 3, ProposerPolicy: &sticky}},
			{WBFT: &types.WBFTParams{EpochLength: 7}}}, types.GenesisInit{}, big.NewInt(1))
	srv := httptest.NewServer(Handler(APIs(fakeBackend{cfg})))
	defer srv.Close()
	call := func(params string) map[string]any {
		t.Helper()
		resp, err := http.Post(srv.URL, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_configAt","params":`+params+`}`))
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
	for params, want := range map[string]string{
		`[9]`:                     `{"number":"9","requestTimeoutMs":2000,"blockPeriodSeconds":1,"epochLength":5,"proposerPolicy":null,"maxRequestTimeoutSeconds":0,"allowedFutureBlockTime":0,"transitions":[]}`,
		`["0xa"]`:                 `{"number":"10","requestTimeoutMs":2000,"blockPeriodSeconds":1,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":0,"allowedFutureBlockTime":0,"transitions":[{"block":"10","wbft":{"requestTimeoutSeconds":0,"blockPeriodSeconds":0,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":null}}]}`,
		`["100"]`:                 `{"number":"100","requestTimeoutMs":2000,"blockPeriodSeconds":1,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":0,"allowedFutureBlockTime":0,"transitions":[{"block":"10","wbft":{"requestTimeoutSeconds":0,"blockPeriodSeconds":0,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":null}}]}`,
		`["0x10000000000000000"]`: `{"number":"18446744073709551616","requestTimeoutMs":2000,"blockPeriodSeconds":1,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":0,"allowedFutureBlockTime":0,"transitions":[{"block":"10","wbft":{"requestTimeoutSeconds":0,"blockPeriodSeconds":0,"epochLength":3,"proposerPolicy":1,"maxRequestTimeoutSeconds":null}}]}`,
	} {
		got := callRaw(t, srv.URL, params)
		if got != want {
			t.Errorf("params %s:\n got %s\nwant %s", params, got, want)
		}
	}
	for _, bad := range []string{`[]`, `["x"]`, `[-1]`, `[1,2]`} {
		if e, ok := call(bad)["error"].(map[string]any); !ok || e["code"] != float64(-32602) {
			t.Errorf("params %s: %v", bad, call(bad))
		}
	}
	none := httptest.NewServer(Handler(APIs(fakeBackend{})))
	defer none.Close()
	resp, err := http.Post(none.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_configAt","params":[1]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out["error"] == nil {
		t.Fatalf("a node without configuration: %v %v", out, err)
	}
}

// callRaw returns the raw result of wbft_configAt with params.
func callRaw(t *testing.T, url, params string) string {
	t.Helper()
	resp, err := http.Post(url, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_configAt","params":`+params+`}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Result json.RawMessage }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return string(out.Result)
}

// TestBlockNumber reads block numbers as go-ethereum's rpc.BlockNumber does:
// the five tags, a QUANTITY, and its error texts otherwise.
func TestBlockNumber(t *testing.T) {
	for in, want := range map[string]BlockNumber{`"earliest"`: 0, `"latest"`: -2, `"pending"`: -1, `"finalized"`: -3,
		`"safe"`: -4, `"0x0"`: 0, `"0x1f"`: 31, `"0X10"`: 16} {
		var n BlockNumber
		if err := json.Unmarshal([]byte(in), &n); err != nil || n != want {
			t.Errorf("%s: %d %v", in, n, err)
		}
	}
	for in, msg := range map[string]string{`""`: "empty hex string", `"5"`: "hex string without 0x prefix", `5`: "hex string without 0x prefix",
		`"0x"`: `hex string "0x"`, `"0x01"`: "hex number with leading zero digits", `"0xg"`: "invalid hex string",
		`"0x10000000000000000"`: "hex number > 64 bits", `"0x8000000000000000"`: "block number larger than int64"} {
		var n BlockNumber
		if err := json.Unmarshal([]byte(in), &n); err == nil || err.Error() != msg {
			t.Errorf("%s: %v, want %q", in, err, msg)
		}
	}
}
