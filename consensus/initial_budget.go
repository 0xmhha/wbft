package consensus

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/types"
)

// ErrInitialRoundBudget reports an ordinary initial round timeout that does
// not exceed its block period under the selected local timing options.
var ErrInitialRoundBudget = errors.New("consensus: insufficient initial round budget")

// CheckInitialRoundBudget checks effective configurations at height zero and
// each distinct transition height when the local option is selected. Node and
// simulation startup call it before opening their consensus state. Direct core
// users must call it at their own configuration boundary. This is a necessary
// timing condition, not a bound on application or network processing time.
// Values outside ordinary positive duration products retain their prior path;
// earlier configuration-unit conversion is not reconstructed here.
func CheckInitialRoundBudget(cfg *types.Config, flags ImprovementSet) error {
	if !flags.Has(RequireInitialRoundBudget) {
		return nil
	}
	if cfg == nil {
		return fmt.Errorf("%w: missing configuration", ErrInitialRoundBudget)
	}
	check := func(h types.Height) error {
		p := cfg.ConfigAt(h)
		if p.RequestTimeoutMs == 0 || p.RequestTimeoutMs > uint64(math.MaxInt64/int64(time.Millisecond)) || p.BlockPeriodSeconds == 0 || p.BlockPeriodSeconds > uint64(math.MaxInt64/int64(time.Second)) || p.MaxRequestTimeoutSeconds > uint64(math.MaxInt64/int64(time.Second)) {
			return nil
		}
		round, _ := roundTimeoutWithOptions(p, types.Round{}, flags)
		period := time.Duration(p.BlockPeriodSeconds) * time.Second
		if round <= period {
			return fmt.Errorf("%w: height %s timeout %s must exceed block period %s", ErrInitialRoundBudget, h.String(), round, period)
		}
		return nil
	}
	var last types.Height
	if err := check(last); err != nil {
		return err
	}
	for _, transition := range cfg.Transitions() {
		if transition.Block == nil {
			break
		}
		h, err := types.HeightFromBig(transition.Block)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInitialRoundBudget, err)
		}
		if h.Cmp(last) == 0 {
			continue
		}
		if err = check(h); err != nil {
			return err
		}
		last = h
	}
	return nil
}
