package rpc

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/types"
)

type observationBandBackend struct {
	fakeBackend
	requests []ObservationBandRequest
}

func (b *observationBandBackend) ObservationBand(q ObservationBandRequest) (*ObservationBandResult, error) {
	b.requests = append(b.requests, q)
	return &ObservationBandResult{Schema: "wbft-observation-band-rpc/1", Status: "AVAILABLE", VerificationScope: "test_backend", Diagnostic: &window.BandDiagnostic{Schema: "wbft-observation-band/1", Address: q.Address.String(), Minimum: q.Minimum}}, nil
}

func TestObservationBandBoundedCanonicalRequest(t *testing.T) {
	full := new(big.Int).Lsh(big.NewInt(1), 128)
	q := ObservationBandRequest{Address: types.Address{1}, View: window.RecentView, Minimum: full.String(), Numerator: "18446744073709551614", Denominator: "18446744073709551615"}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservationBandRequest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	p, err := decoded.Policy(types.MustHeightFromBig(full))
	if err != nil {
		t.Fatal(err)
	}
	if p.Minimum.Big().Cmp(full) != 0 || decoded != q {
		t.Fatal("request integer precision changed")
	}
	if _, err := decoded.Policy(types.HeightFromUint64(3)); !errors.Is(err, errParams) {
		t.Fatal("impossible minimum accepted")
	}
	valid := string(raw)
	for _, bad := range []string{
		"null", "{}", "[]",
		strings.Replace(valid, `"address":"`+q.Address.String()+`",`, "", 1),
		strings.Replace(valid, `"minimum":"`+full.String()+`"`, `"minimum":3`, 1),
		strings.Replace(valid, `"minimum":"`+full.String()+`"`, `"minimum":"0`+full.String()+`"`, 1),
		strings.Replace(valid, `"minimum":"`+full.String()+`"`, `"minimum":"`+strings.Repeat("1", 257)+`"`, 1),
		strings.Replace(valid, `"recent_preview"`, `"other"`, 1),
		strings.Replace(valid, `"18446744073709551615"`, `"18446744073709551616"`, 1),
		strings.Replace(valid, `"18446744073709551615"`, `"0"`, 1),
		`{"address":"` + q.Address.String() + `","view":"settled","minimum":"1","numerator":"3","denominator":"2"}`,
		strings.TrimSuffix(valid, "}") + `,"verified":true}`,
		strings.TrimSuffix(valid, "}") + `,"eligible":"3"}`,
		strings.TrimSuffix(valid, "}") + `,"padding":"` + strings.Repeat(" ", 1025) + `"}`,
	} {
		if bad == valid {
			t.Fatal("invalid request fixture unchanged")
		}
		if err := json.Unmarshal([]byte(bad), &decoded); err == nil {
			t.Fatalf("invalid request accepted: %.90s", bad)
		}
	}
}

func TestObservationBandHTTPAndOptionalCapability(t *testing.T) {
	b := &observationBandBackend{}
	h := Handler(APIs(b))
	q := ObservationBandRequest{Address: types.Address{1}, View: window.SettledView, Minimum: "3", Numerator: "4", Denominator: "5"}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	call := func(handler http.Handler, params string) map[string]any {
		t.Helper()
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wbft_observationBand","params":`+params+`}`)))
		var result map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := call(h, "["+string(raw)+"]")
	if result["error"] != nil || result["result"].(map[string]any)["status"] != "AVAILABLE" || len(b.requests) != 1 || b.requests[0] != q {
		t.Fatal(result, b.requests)
	}
	for _, params := range []string{"[]", "[null]", "[{},{}]", "[{}]", "[" + strings.TrimSuffix(string(raw), "}") + `,"state_root":"claimed"}]`} {
		r := call(h, params)
		if r["error"].(map[string]any)["code"] != float64(-32602) {
			t.Fatal(r)
		}
	}
	if len(b.requests) != 1 {
		t.Fatal("bad request reached backend")
	}
	unsupported := call(Handler(APIs(fakeBackend{})), "["+string(raw)+"]")
	if unsupported["result"].(map[string]any)["status"] != "UNSUPPORTED" {
		t.Fatal(unsupported)
	}
}
