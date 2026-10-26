package window_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"testing"

	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/types"
)

func TestRecentDiagnosticSnapshotsAndIndependentRationalOracle(t *testing.T) {
	c := normalRetention(t, 4, types.HeightFromUint64(1), false, types.HeightFromUint64(3), 36)
	seen := map[string]bool{}
	for _, n := range []int{0, 3, 6, 8, 12, 16, 17, 18, 24, 30, 36} {
		beforeRoot, err := c.engine.Root(c.states[n])
		must(t, err)
		var before []byte
		if n > 0 {
			before, err = c.engine.EncodeCheckpoint(c.states[n], c.headers[n])
			must(t, err)
		}
		for _, view := range []state.DiagnosticView{state.SettledView, state.RecentView} {
			for _, id := range []int{0, 1, 4, 5, 99} {
				for _, minimum := range []uint64{1, 3} {
					for _, fraction := range [][2]uint64{{1, 1}, {4, 5}, {1, 2}, {math.MaxUint64 - 1, math.MaxUint64}} {
						p := state.BandPolicy{Minimum: types.HeightFromUint64(minimum), Numerator: fraction[0], Denominator: fraction[1]}
						got, err := c.engine.DiagnoseRecent(c.states[n], address(id), view, p)
						must(t, err)
						from, through, _ := c.states[n].SettledWindow()
						row, _ := c.states[n].Counts(address(id))
						if view == state.RecentView {
							from, through, _ = c.states[n].RecentWindow()
							row, _ = c.states[n].RecentCounts(address(id))
						}
						root, err := c.engine.Root(c.states[n])
						must(t, err)
						if got.View != view || got.From != from.String() || got.Through != through.String() || got.CarrierHeight != c.headers[n].Number.String() || got.StateRoot != root.String() || got.ObservationPolicy != c.engine.Digest().String() || got.CarrierHash != parentHash(t, c.history, c.headers[n]).String() || got.Address != address(id).String() {
							t.Fatal("diagnostic source or snapshot mismatch")
						}
						if got.Eligible != row.EligiblePrepare.String() || got.ObservedPrepare != row.ObservedPrepare.String() || got.ObservedCommit != row.ObservedCommit.String() {
							t.Fatal("diagnostic counts differ from labelled snapshot")
						}
						want := "SUFFICIENT_HISTORY"
						if row.EligiblePrepare.Sign() == 0 {
							want = "NO_HISTORY"
						} else if row.EligiblePrepare.Cmp(p.Minimum.Big()) < 0 {
							want = "INSUFFICIENT_HISTORY"
						}
						if got.HistoryStatus != want || (got.ObservedBand == nil) != (want != "SUFFICIENT_HISTORY") {
							t.Fatal("unknown history classified as a numeric score")
						}
						seen[want] = true
						if got.ObservedBand != nil {
							// big.Rat is an independent oracle for the integer-product implementation.
							target := new(big.Rat).SetFrac(new(big.Int).SetUint64(p.Numerator), new(big.Int).SetUint64(p.Denominator))
							prepare := new(big.Rat).SetFrac(row.ObservedPrepare, row.EligiblePrepare)
							commit := new(big.Rat).SetFrac(row.ObservedCommit, row.EligibleCommit)
							within := prepare.Cmp(target) >= 0 && commit.Cmp(target) >= 0
							if (*got.ObservedBand == "IN_OBSERVED_BAND") != within {
								t.Fatal("phase classification differs from rational oracle")
							}
							seen[*got.ObservedBand] = true
							*got.ObservedBand = "caller-owned"
						}
						encoded, err := json.Marshal(got)
						must(t, err)
						var fields map[string]any
						must(t, json.Unmarshal(encoded, &fields))
						for _, key := range []string{"eligible", "observed_prepare", "observed_commit", "minimum", "numerator", "denominator", "carrier_height", "from", "through", "retention"} {
							if _, ok := fields[key].(string); !ok {
								t.Fatalf("lossy JSON field %s", key)
							}
						}
					}
				}
			}
		}
		afterRoot, err := c.engine.Root(c.states[n])
		must(t, err)
		if beforeRoot != afterRoot {
			t.Fatal("diagnosis changed observation state")
		}
		if n > 0 {
			after, err := c.engine.EncodeCheckpoint(c.states[n], c.headers[n])
			must(t, err)
			if !bytes.Equal(before, after) {
				t.Fatal("diagnosis changed checkpoint bytes")
			}
		}
	}
	for _, label := range []string{"NO_HISTORY", "INSUFFICIENT_HISTORY", "SUFFICIENT_HISTORY", "IN_OBSERVED_BAND", "BELOW_OBSERVED_BAND"} {
		if !seen[label] {
			t.Fatalf("missing normal fixture outcome %s", label)
		}
	}
}

func TestRecentDiagnosticPolicyErrorsAndFullHeight(t *testing.T) {
	a := types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 90))
	e, s, _, parent := initialRetention(t, 4, a, types.HeightFromUint64(3))
	p := state.BandPolicy{Minimum: types.HeightFromUint64(1), Numerator: 8, Denominator: 10}
	got, err := e.DiagnoseRecent(s, address(99), state.SettledView, p)
	must(t, err)
	if got.CarrierHeight != parent.Number.String() || got.Numerator != "4" || got.Denominator != "5" || got.ObservedBand != nil || got.HistoryStatus != "NO_HISTORY" {
		t.Fatal("height truncated, fraction not normalized, or empty history classified")
	}
	for _, invalid := range []state.BandPolicy{
		{}, {Minimum: types.HeightFromUint64(4), Numerator: 1, Denominator: 1},
		{Minimum: p.Minimum, Numerator: 0, Denominator: 1},
		{Minimum: p.Minimum, Numerator: 1, Denominator: 0},
		{Minimum: p.Minimum, Numerator: 3, Denominator: 2},
	} {
		if _, err := e.DiagnoseRecent(s, address(0), state.RecentView, invalid); !errors.Is(err, state.ErrPolicy) {
			t.Fatal("invalid policy accepted")
		}
	}
	if _, err := e.DiagnoseRecent(s, address(0), "other", p); !errors.Is(err, state.ErrPolicy) {
		t.Fatal("invalid view accepted")
	}
	if _, err := e.DiagnoseRecent(nil, address(0), state.RecentView, p); !errors.Is(err, state.ErrState) {
		t.Fatal("unavailable state converted to NO_HISTORY")
	}
	legacy, cumulative, _, _ := initial(t, 4, a)
	if _, err := legacy.DiagnoseRecent(cumulative, address(0), state.RecentView, p); !errors.Is(err, state.ErrPolicy) {
		t.Fatal("cumulative state treated as recent")
	}
	if _, err := e.DiagnoseRecent(cumulative, address(0), state.RecentView, p); !errors.Is(err, state.ErrState) {
		t.Fatal("foreign policy state accepted")
	}
}
