package consensus

import (
	"math"
	"time"

	"github.com/0xmhha/wbft/types"
)

// TimeoutWarning names the warning the reference logs while computing a
// round timeout.
type TimeoutWarning uint8

// Timeout warnings.
const (
	// NoWarning: the timeout was computed without a warning.
	NoWarning TimeoutWarning = iota
	// CapOverflowGuard: the capped computation ended below the base timeout
	// and the cap was used.
	CapOverflowGuard
	// MaxInt64Clamp: the uncapped computation was NaN, infinite or above
	// 2^63 in binary64 and the timeout was clamped to MaxInt64 nanoseconds.
	MaxInt64Clamp
)

func (w TimeoutWarning) String() string {
	switch w {
	case NoWarning:
		return "none"
	case CapOverflowGuard:
		return "cap_overflow_guard"
	case MaxInt64Clamp:
		return "max_int64_clamp"
	}
	return "unknown"
}

// twoPow63 is float64(math.MaxInt64): 2^63 after rounding.
const twoPow63 = float64(1 << 63)

// RoundTimeout is round_timeout(config_at(h), r): the duration of the
// round-change timer of a view with round r, with the 64-bit arithmetic of
// the reference.
//
// base = RequestTimeoutMs ms and cap = MaxRequestTimeoutSeconds s are int64
// nanosecond products that wrap. With cap > 0 the base is doubled r times
// (wrapping), stopping at the first value above the cap, which is then used;
// a result below the base is replaced by the cap (CapOverflowGuard). Round 0
// is never capped. Otherwise the timeout is 2^r · base in binary64, clamped to
// MaxInt64 when that is NaN, infinite or above 2^63 (MaxInt64Clamp), and
// truncated toward zero.
//
// Spec: WBFT-TIMER-005, WBFT-TIMER-006, WBFT-TIMER-007, WBFT-TIMER-008
func RoundTimeout(p types.Params, r types.Round) (time.Duration, TimeoutWarning) {
	base := time.Duration(p.RequestTimeoutMs) * time.Millisecond
	roundNum := r.RefLow64() //wbft:low64 HH-72
	maxTimeout := time.Duration(p.MaxRequestTimeoutSeconds) * time.Second

	if maxTimeout > 0 {
		timeout := base
		for i := uint64(0); i < roundNum; i++ {
			timeout = timeout * 2
			if timeout > maxTimeout {
				timeout = maxTimeout
				break
			}
		}
		if timeout < base {
			return maxTimeout, CapOverflowGuard
		}
		return timeout, NoWarning
	}

	// 2^r is exact in binary64 for r < 1024 and +Inf above, as
	// math.Pow(2, float64(r)) gives it.
	var pow float64
	if roundNum < 1024 {
		pow = math.Ldexp(1, int(roundNum))
	} else {
		pow = math.Inf(1)
	}
	f := float64(pow * float64(base))
	if math.IsNaN(f) || math.IsInf(f, 0) || f > twoPow63 {
		return time.Duration(math.MaxInt64), MaxInt64Clamp
	}
	if f < -twoPow63 {
		// Out of the int64 range below: amd64 and arm64 both convert such
		// a value to MinInt64; the conversion is made explicit here.
		return time.Duration(math.MinInt64), NoWarning
	}
	return time.Duration(int64(f)), NoWarning
}

// BuildWait is the wait of the block builder before it builds a proposal
// after a round started: for a requested round 0 (its low 64 bits) the time
// from nowUnixNano until the second headTime + blockPeriod, and 0 when that
// time has passed; for any other round 0. The difference saturates like
// time.Time.Sub.
//
// Spec: WBFT-TIMER-040, WBFT-TIMER-041
func BuildWait(headTime, blockPeriod uint64, round types.Round, nowUnixNano int64) time.Duration {
	if round.RefLow64() != 0 { //wbft:low64 HH-70
		return 0
	}
	next := time.Unix(int64(headTime+blockPeriod), 0)
	d := next.Sub(time.Unix(0, nowUnixNano))
	if d < 0 {
		return 0
	}
	return d
}

// Wait returns BuildWait of the request at nowUnixNano.
func (r RequestBuild) Wait(nowUnixNano int64) time.Duration {
	return BuildWait(r.HeadTime, r.BlockPeriod, r.Round, nowUnixNano)
}
