package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"strconv"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/types"
)

// ObservationBandRequest describes one address at the node's adopted observation
// state. All diagnostic parameters are explicit; no history is fetched on demand.
// Decimal strings preserve precision. Minimum is bounded to 256 digits, and the
// rational threshold is bounded to uint64 before any diagnostic work begins.
type ObservationBandRequest struct {
	Address     types.Address         `json:"address"`
	View        window.DiagnosticView `json:"view"`
	Minimum     string                `json:"minimum"`
	Numerator   string                `json:"numerator"`
	Denominator string                `json:"denominator"`
}

func positiveDecimal(s string, max int) bool {
	if len(s) == 0 || len(s) > max || s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Check rejects noncanonical or unbounded inputs before calling a backend.
func (q ObservationBandRequest) Check() error {
	if !positiveDecimal(q.Minimum, 256) || !positiveDecimal(q.Numerator, 20) || !positiveDecimal(q.Denominator, 20) ||
		(q.View != window.SettledView && q.View != window.RecentView) {
		return errParams
	}
	a, ea := strconv.ParseUint(q.Numerator, 10, 64)
	b, eb := strconv.ParseUint(q.Denominator, 10, 64)
	if ea != nil || eb != nil || a > b {
		return errParams
	}
	return nil
}

// UnmarshalJSON keeps the request closed in both the HTTP adapter and RPC
// servers that reflect exported Service methods. A client cannot supply counts,
// a state root, an authentication claim or an unbounded integer to this method.
func (q *ObservationBandRequest) UnmarshalJSON(raw []byte) error {
	if len(raw) > 1024 {
		return errParams
	}
	var input struct {
		Address     *types.Address        `json:"address"`
		View        window.DiagnosticView `json:"view"`
		Minimum     string                `json:"minimum"`
		Numerator   string                `json:"numerator"`
		Denominator string                `json:"denominator"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || input.Address == nil || d.Decode(new(any)) != io.EOF {
		return errParams
	}
	value := ObservationBandRequest{Address: *input.Address, View: input.View, Minimum: input.Minimum, Numerator: input.Numerator, Denominator: input.Denominator}
	if err := value.Check(); err != nil {
		return err
	}
	*q = value
	return nil
}

// Policy checks the minimum against the actual runtime retention policy.
func (q ObservationBandRequest) Policy(retention types.Height) (window.BandPolicy, error) {
	if err := q.Check(); err != nil {
		return window.BandPolicy{}, err
	}
	n, _ := new(big.Int).SetString(q.Minimum, 10)
	m := types.MustHeightFromBig(n)
	if m.Cmp(retention) > 0 {
		return window.BandPolicy{}, errParams
	}
	a, _ := strconv.ParseUint(q.Numerator, 10, 64)
	b, _ := strconv.ParseUint(q.Denominator, 10, 64)
	return window.BandPolicy{Minimum: m, Numerator: a, Denominator: b}, nil
}

// ObservationBandResult distinguishes service availability from sample history.
// AVAILABLE means this node read its locally adopted state. A remote client must
// retain the node's provenance claim; it is not independent chain verification.
// No client-provided counts or self-declared verification flags are accepted.
type ObservationBandResult struct {
	Schema            string                 `json:"schema"`
	Status            string                 `json:"status"`
	Reason            string                 `json:"reason,omitempty"`
	ChainID           string                 `json:"chain_id,omitempty"`
	GenesisHash       string                 `json:"genesis_hash,omitempty"`
	CoreVersion       string                 `json:"core_version,omitempty"`
	VerificationScope string                 `json:"verification_scope,omitempty"`
	Diagnostic        *window.BandDiagnostic `json:"diagnostic,omitempty"`
}

// ObservationBandBackend is optional. Existing Backend implementations do not
// gain simulated support by satisfying the original interface.
type ObservationBandBackend interface {
	ObservationBand(ObservationBandRequest) (*ObservationBandResult, error)
}

// ObservationBand is wbft_observationBand, a bounded read-only query. It does
// not change participation recording, observation policy, selection or fees.
func (s *Service) ObservationBand(q ObservationBandRequest) (*ObservationBandResult, error) {
	if err := q.Check(); err != nil {
		return nil, err
	}
	b, ok := s.b.(ObservationBandBackend)
	if !ok {
		return &ObservationBandResult{Schema: "wbft-observation-band-rpc/1", Status: "UNSUPPORTED", Reason: "backend_has_no_observation_band_capability"}, nil
	}
	return b.ObservationBand(q)
}
