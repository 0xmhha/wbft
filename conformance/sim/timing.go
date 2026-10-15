package sim

import (
	"fmt"
	"maps"
	"math"
	"time"
)

// TimingParams changes one node's timeouts and minimum block period without
// changing chain membership, proposer policy, epoch length or private state.
type TimingParams struct {
	RequestTimeoutSeconds    *uint64 `json:"request_timeout_seconds,omitempty"`
	BlockPeriodSeconds       *uint64 `json:"block_period_seconds,omitempty"`
	MaxRequestTimeoutSeconds *uint64 `json:"max_request_timeout_seconds,omitempty"`
}

func cloneTimingValue(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneTiming(p *TimingParams) *TimingParams {
	if p == nil {
		return nil
	}
	return &TimingParams{RequestTimeoutSeconds: cloneTimingValue(p.RequestTimeoutSeconds), BlockPeriodSeconds: cloneTimingValue(p.BlockPeriodSeconds), MaxRequestTimeoutSeconds: cloneTimingValue(p.MaxRequestTimeoutSeconds)}
}

// ResolveTiming overlays explicitly supplied values on normalized scenario
// parameters. It never applies the simulator's zero-valued global defaults to
// an explicit override. The cap may be zero; timeout and block period may not.
// Explicit values must fit the duration domain when added to the horizon.
// Derived round timeouts retain their existing protocol arithmetic.
func ResolveTiming(base Params, override *TimingParams, horizon time.Duration) (Params, error) {
	out := base
	out.RuleActivations = maps.Clone(base.RuleActivations)
	out.AllowedFutureBlockTime = cloneTimingValue(base.AllowedFutureBlockTime)
	out.MaxRequestTimeoutSeconds = cloneTimingValue(base.MaxRequestTimeoutSeconds)
	if override == nil {
		return out, nil
	}
	if horizon <= 0 {
		return Params{}, fmt.Errorf("%w: invalid timing horizon", ErrScenario)
	}
	maximum := uint64((time.Duration(math.MaxInt64) - horizon) / time.Second)
	valid := func(value *uint64, zero bool) bool { return value == nil || (zero || *value > 0) && *value <= maximum }
	if !valid(override.RequestTimeoutSeconds, false) || !valid(override.BlockPeriodSeconds, false) || !valid(override.MaxRequestTimeoutSeconds, true) {
		return Params{}, fmt.Errorf("%w: node timing outside representable duration", ErrScenario)
	}
	if override.RequestTimeoutSeconds != nil {
		out.RequestTimeoutSeconds = *override.RequestTimeoutSeconds
	}
	if override.BlockPeriodSeconds != nil {
		out.BlockPeriodSeconds = *override.BlockPeriodSeconds
	}
	if override.MaxRequestTimeoutSeconds != nil {
		out.MaxRequestTimeoutSeconds = cloneTimingValue(override.MaxRequestTimeoutSeconds)
	}
	return out, nil
}
