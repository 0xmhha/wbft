package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/rpc"
)

// TestIstanbul checks the compatible istanbul namespace on one validator
// against spec B-09 §8: results, the reference's error texts and the closed
// method set.
func TestIstanbul(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	defer stop(t, n)
	a.waitHead(t, 3, 20*time.Second)
	srv := httptest.NewServer(rpc.Handler(n.APIs()))
	defer srv.Close()
	type reply struct {
		Result json.RawMessage
		Error  *struct {
			Code    int
			Message string
		}
	}
	call := func(method, params string) reply {
		t.Helper()
		resp, err := http.Post(srv.URL, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var r reply
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	ok := func(method, params, want string) {
		t.Helper()
		if r := call(method, params); r.Error != nil || string(r.Result) != want {
			t.Errorf("%s%s = %s %+v, want %s", method, params, r.Result, r.Error, want)
		}
	}
	fail := func(method, params string, code int, msg string) {
		t.Helper()
		if r := call(method, params); r.Error == nil || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
			t.Errorf("%s%s = %s %+v, want %d %q", method, params, r.Result, r.Error, code, msg)
		}
	}
	self := strings.ToLower(n.Address().Hex())
	h1 := a.HeaderByNumber(1)
	hash1 := strings.ToLower(codec.BlockHash(h1).Hex())

	ok("istanbul_nodeAddress", `[]`, `"`+self+`"`)
	// Committers of block 1 and its author (the coinbase): a JSON number
	// and lowercase addresses; by hash the same.
	signers := `{"Number":1,"Hash":"` + hash1 + `","Author":"` + strings.ToLower(h1.Coinbase.Hex()) + `","Committers":["` + self + `"]}`
	ok("istanbul_getCommitSignersFromBlock", `["0x1"]`, signers)
	ok("istanbul_getCommitSignersFromBlockByHash", `["`+hash1+`"]`, signers)
	fail("istanbul_getCommitSignersFromBlock", `["0x0"]`, -32000, "zero seals") // the genesis has no committed seal
	fail("istanbul_getCommitSignersFromBlock", `["pending"]`, -32000, "unknown block")
	if r := call("istanbul_getCommitSignersFromBlock", `[]`); r.Error != nil || !strings.Contains(string(r.Result), `"Committers":["`+self+`"]`) {
		t.Errorf("signers of the head: %s %+v", r.Result, r.Error)
	}
	ok("istanbul_getValidators", `["0x0"]`, `["`+self+`"]`)
	ok("istanbul_getValidators", `[]`, `["`+self+`"]`)
	ok("istanbul_getValidatorsAtHash", `["`+hash1+`"]`, `["`+self+`"]`)
	ok("istanbul_isValidator", `[]`, `true`)
	ok("istanbul_isValidator", `["pending"]`, `false`) // no set: false, not an error
	// Two blocks decided in round 0, each sealed and authored by the
	// validator; its parent's set signs the prev seals.
	if r := call("istanbul_status", `["0x2","0x3"]`); r.Error != nil || !strings.HasPrefix(string(r.Result), `{"sealerActivity":{"total":{"`+self+`":`) ||
		!strings.Contains(string(r.Result), `"blockRange":{"startBlock":2,"endBlock":3,"totalBlocks":2},"roundStats":{"roundDistribution":{"0":2}}}`) ||
		!strings.Contains(string(r.Result), `"author":{"`+self+`":2}`) || !strings.Contains(string(r.Result), `"committed":{"`+self+`":2}`) {
		t.Errorf("status 2..3 = %s %+v", r.Result, r.Error)
	}
	fail("istanbul_status", `["0x1"]`, -32000, "pass the end block number")
	fail("istanbul_status", `[null,"0x1"]`, -32000, "pass the start block number")
	fail("istanbul_status", `["0x3","0x2"]`, -32000, "start block number should be less than end block number")
	fail("istanbul_status", `["0x1","0xfffff"]`, -32000, "end block number should be less than or equal to current block height")
	fail("istanbul_status", `["pending","latest"]`, -32000, "unsupported block number: -1")
	// getWbftExtraInfo: checksummed sealers, the gas tip in decimal, the
	// round in hex; latest is -2 for its non-pointer argument.
	r := call("istanbul_getWbftExtraInfo", `["0x1"]`)
	var x map[string]any
	if r.Error != nil || json.Unmarshal(r.Result, &x) != nil {
		t.Fatalf("extra of block 1: %s %+v", r.Result, r.Error)
	}
	cs, _ := x["committedSeal"].(map[string]any)
	if x["round"] != "0x0" || cs == nil || cs["sealers"].([]any)[0] != n.Address().Hex() || strings.HasPrefix(x["gasTip"].(string), "0x") ||
		x["epochInfo"] != nil {
		t.Errorf("extra of block 1: %v", x)
	}
	if r := call("istanbul_getWbftExtraInfo", `["0x0"]`); r.Error != nil || !strings.Contains(string(r.Result), `"epochInfo":{"candidates":[{"addr":"`+n.Address().Hex()+`"`) {
		t.Errorf("extra of the genesis: %s %+v", r.Result, r.Error)
	}
	fail("istanbul_getWbftExtraInfo", `["latest"]`, -32000, "block -2 not found")
	// The namespace is closed: the Quorum methods are not there.
	for _, m := range []string{"istanbul_getSignersFromBlock", "istanbul_getSnapshot", "istanbul_candidates", "istanbul_propose", "istanbul_discard"} {
		fail(m, `[]`, -32601, "method not found")
	}
}
