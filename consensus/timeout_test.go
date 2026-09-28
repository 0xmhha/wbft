package consensus

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

// referenceTimeout is the computation of the reference written out with
// math.Pow, as the reference does it, to check RoundTimeout bit for bit.
func referenceTimeout(rtMs, maxS uint64, round uint64) (time.Duration, TimeoutWarning) {
	base := time.Duration(rtMs) * time.Millisecond
	maxT := time.Duration(maxS) * time.Second
	if maxT > 0 {
		t := base
		for i := uint64(0); i < round; i++ {
			t = t * 2
			if t > maxT {
				t = maxT
				break
			}
		}
		if t < base {
			return maxT, CapOverflowGuard
		}
		return t, NoWarning
	}
	f := math.Pow(2, float64(round)) * float64(base)
	if math.IsNaN(f) || math.IsInf(f, 0) || f > float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64), MaxInt64Clamp
	}
	if f < -twoPow63 {
		return time.Duration(math.MinInt64), NoWarning
	}
	return time.Duration(int64(f)), NoWarning
}

func TestRoundTimeoutMatchesReferenceFormula(t *testing.T) {
	configs := []struct{ rt, max uint64 }{
		{2000, 0}, {1000, 0}, {2000, 4}, {2000, 10}, {2000, 60}, {1_000_000, 4},
		{2000, 10_000_000_000},  // cap wraps negative: uncapped branch
		{2000, 18_446_744_074},  // cap wraps to a small positive value
		{1, 4_611_686_019},      // cap above 2^62 ns
		{2000, 9_223_372_036},   // doubling wraps through negative values
		{9_223_372_037_000, 10}, // base wraps negative, capped
		{9_223_372_037_000, 0},  // base wraps negative, uncapped
		{18_446_744_073_709, 0}, // base wraps again
	}
	for _, c := range configs {
		p := types.Params{RequestTimeoutMs: c.rt, MaxRequestTimeoutSeconds: c.max}
		for r := uint64(0); r <= 1100; r++ {
			got, gw := RoundTimeout(p, types.RoundFromUint64(r))
			want, ww := referenceTimeout(c.rt, c.max, r)
			if got != want || gw != ww {
				t.Fatalf("rt=%d max=%d r=%d: %d %s, want %d %s", c.rt, c.max, r, got, gw, want, ww)
			}
		}
	}
}

// Fixed values of A-06 §4.2 and §4.4 and of the reference (timers/round_timeout).
func TestRoundTimeoutTable(t *testing.T) {
	two64plus3, _ := types.RoundFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(3)))
	tests := []struct {
		rt, max uint64
		round   types.Round
		want    int64
		warn    TimeoutWarning
	}{
		{2000, 0, types.RoundFromUint64(3), 16_000_000_000, NoWarning},
		{2000, 10, types.RoundFromUint64(3), 10_000_000_000, NoWarning},
		{1_000_000, 4, types.RoundFromUint64(0), 1_000_000_000_000, NoWarning},
		{1_000_000, 4, types.RoundFromUint64(1), 4_000_000_000, CapOverflowGuard},
		{2000, 0, types.RoundFromUint64(32), 8_589_934_592_000_000_000, NoWarning},
		{2000, 0, types.RoundFromUint64(33), math.MaxInt64, MaxInt64Clamp},
		{2000, 10_000_000_000, types.RoundFromUint64(3), 16_000_000_000, NoWarning},
		{2000, 18_446_744_074, types.RoundFromUint64(3), 290_448_384, CapOverflowGuard},
		{2000, 2, types.RoundFromUint64(5), 2_000_000_000, NoWarning},
		{1, 4_611_686_019, types.RoundFromUint64(70), 4_611_686_019_000_000_000, NoWarning},
		{2000, 9_223_372_036, types.RoundFromUint64(70), 9_223_372_036_000_000_000, CapOverflowGuard},
		{9_223_372_037_000, 10, types.RoundFromUint64(0), -9_223_372_036_709_551_616, NoWarning},
		{2000, 0, two64plus3, 16_000_000_000, NoWarning},
		{2000, 0, types.RoundFromUint64(1024), math.MaxInt64, MaxInt64Clamp},
	}
	for _, tt := range tests {
		got, w := RoundTimeout(types.Params{RequestTimeoutMs: tt.rt, MaxRequestTimeoutSeconds: tt.max}, tt.round)
		if int64(got) != tt.want || w != tt.warn {
			t.Errorf("rt=%d max=%d r=%s: %d %s, want %d %s", tt.rt, tt.max, tt.round, got, w, tt.want, tt.warn)
		}
	}
	// A negative uncapped value below -2^63 is MinInt64.
	got, _ := RoundTimeout(types.Params{RequestTimeoutMs: 9_223_372_037_000}, types.RoundFromUint64(3))
	if got >= 0 {
		t.Errorf("negative base: %d", got)
	}
}
