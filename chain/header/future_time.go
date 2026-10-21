package header

import (
	"math"
	"time"

	"github.com/0xmhha/wbft/types"
)

// effectiveFutureAllowance selects one policy for both H2 and its retry
// target. Outside ordinary seconds-to-nanoseconds products, both retain the
// reference path. This does not recover earlier configuration conversions.
func effectiveFutureAllowance(cfg *types.Config, h *types.Header, enabled bool) (uint64, bool) {
	if !enabled {
		return 0, false
	}
	allowance := cfg.FutureTimeAllowanceAt(h.Number)
	const ordinarySeconds = uint64(math.MaxInt64 / int64(time.Second))
	if h.Time > ordinarySeconds || allowance > ordinarySeconds {
		return 0, false
	}
	return allowance, true
}

func futureHeader(cfg *types.Config, h *types.Header, now time.Time, enabled bool) bool {
	if allowance, selected := effectiveFutureAllowance(cfg, h, enabled); selected {
		seconds := int64(allowance)
		at := now.Unix()
		if at > math.MaxInt64-seconds {
			return false
		}
		adjusted := at + seconds
		return adjusted < 0 || h.Time > uint64(adjusted)
	}
	allowance := cfg.Base().AllowedFutureBlockTime
	adjusted := now.Add(time.Duration(allowance) * time.Second).Unix()
	return h.Time > uint64(adjusted)
}

func futureProposalWait(env *Env, h *types.Header) time.Duration {
	now := env.Now()
	if allowance, selected := effectiveFutureAllowance(env.Config, h, env.UseFutureTimeAllowance); selected {
		return time.Unix(int64(h.Time)-int64(allowance), 0).Sub(now)
	}
	return time.Unix(int64(h.Time), 0).Sub(now)
}
