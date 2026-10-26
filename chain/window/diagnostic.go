package window

import (
	"math/big"
	"strconv"

	"github.com/0xmhha/wbft/types"
)

// BandPolicy supplies an explicit minimum target count and an inclusive
// threshold Numerator/Denominator for each phase. It has no network defaults
// and is independent of the observation engine's consensus commitment.
type BandPolicy struct {
	Minimum                types.Height
	Numerator, Denominator uint64
}

// DiagnosticView selects one complete snapshot, never a mixture of cursors.
type DiagnosticView string

const (
	SettledView DiagnosticView = "settled"
	RecentView  DiagnosticView = "recent_preview"
)

// BandDiagnostic is a read-only description of one address in a recent policy.
// Exact integers are decimal strings. A nil ObservedBand means no classification
// is available, not a zero score. Below-band observations do not prove a signer
// withheld a signature, and this result must not be used as blacklist eligibility,
// candidate diligence, a validator list or a fee weight.
//
// CarrierHash, StateRoot and ObservationPolicy identify the supplied state;
// they do not authenticate it. The caller must supply a state derived from
// authenticated history or an independently trusted checkpoint anchor.
type BandDiagnostic struct {
	Schema            string         `json:"schema"`
	View              DiagnosticView `json:"view"`
	CarrierHash       string         `json:"carrier_hash"`
	CarrierHeight     string         `json:"carrier_height"`
	StateRoot         string         `json:"state_root"`
	ObservationPolicy string         `json:"observation_policy"`
	Retention         string         `json:"retention"`
	From              string         `json:"from"`
	Through           string         `json:"through"`
	Address           string         `json:"address"`
	Eligible          string         `json:"eligible"`
	ObservedPrepare   string         `json:"observed_prepare"`
	ObservedCommit    string         `json:"observed_commit"`
	Minimum           string         `json:"minimum"`
	Numerator         string         `json:"numerator"`
	Denominator       string         `json:"denominator"`
	HistoryStatus     string         `json:"history_status"`
	ObservedBand      *string        `json:"observed_band"`
}

// DiagnoseRecent classifies each phase separately using exact integer products.
// Minimum counts historical targets, not the sum of phase opportunities.
// SettledView reads Counts/SettledWindow; RecentView reads the independently
// labelled RecentCounts/RecentWindow. Cumulative policies, invalid views, zero
// or impossible minima, and thresholds outside (0,1] return ErrPolicy. Invalid
// states remain errors and are never converted to NO_HISTORY.
//
// This method changes no engine, state, header, epoch, selection or fee rule.
// External adapters must bound requests and authenticate provenance before
// describing a diagnostic as a verified chain observation.
func (e *Engine) DiagnoseRecent(s *State, address types.Address, view DiagnosticView, p BandPolicy) (*BandDiagnostic, error) {
	if e == nil || e.retention.IsZero() || (view != SettledView && view != RecentView) ||
		p.Minimum.IsZero() || p.Minimum.Cmp(e.retention) > 0 || p.Numerator == 0 || p.Numerator > p.Denominator {
		return nil, ErrPolicy
	}
	root, err := e.Root(s)
	if err != nil {
		return nil, err
	}
	from, through, _ := s.SettledWindow()
	row, _ := s.Counts(address)
	if view == RecentView {
		from, through, _ = s.RecentWindow()
		row, _ = s.RecentCounts(address)
	}
	num, den := p.Numerator, p.Denominator
	a, b := num, den
	for b != 0 {
		a, b = b, a%b
	}
	num, den = num/a, den/a
	out := &BandDiagnostic{
		Schema: "wbft-observation-band/1", View: view,
		CarrierHash: s.anchor.String(), CarrierHeight: s.Height().String(),
		StateRoot: root.String(), ObservationPolicy: e.Digest().String(),
		Retention: e.retention.String(), From: from.String(), Through: through.String(),
		Address: address.String(), Eligible: row.EligiblePrepare.String(),
		ObservedPrepare: row.ObservedPrepare.String(), ObservedCommit: row.ObservedCommit.String(),
		Minimum: p.Minimum.String(), Numerator: strconv.FormatUint(num, 10), Denominator: strconv.FormatUint(den, 10),
		HistoryStatus: "NO_HISTORY",
	}
	n := row.EligiblePrepare
	if n.Sign() == 0 {
		return out, nil
	}
	out.HistoryStatus = "INSUFFICIENT_HISTORY"
	if n.Cmp(p.Minimum.Big()) < 0 {
		return out, nil
	}
	out.HistoryStatus = "SUFFICIENT_HISTORY"
	threshold := new(big.Int).Mul(n, new(big.Int).SetUint64(num))
	prepare := new(big.Int).Mul(row.ObservedPrepare, new(big.Int).SetUint64(den))
	commit := new(big.Int).Mul(row.ObservedCommit, new(big.Int).SetUint64(den))
	band := "BELOW_OBSERVED_BAND"
	if prepare.Cmp(threshold) >= 0 && commit.Cmp(threshold) >= 0 {
		band = "IN_OBSERVED_BAND"
	}
	out.ObservedBand = &band
	return out, nil
}
