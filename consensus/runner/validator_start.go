package runner

import "github.com/0xmhha/wbft/consensus"

// restoreTimerWidth preserves the original four-counter source envelope
// unless the fifth local timer was explicitly selected.
func (r *Runner) restoreTimerWidth() int {
	if r.cfg.Core.Improvements.Has(consensus.DeferValidatorStart) {
		return 5
	}
	return 4
}

// cancelValidatorStartBuild releases only this runner's old builder work.
// The core gates late requests; this cancellation does not authorize a new
// height or evict an application's committed-block cache.
func (r *Runner) cancelValidatorStartBuild() {
	if r.core.ValidatorStartWait() != nil && r.buildDone != nil {
		close(r.buildDone)
		r.buildDone = nil
	}
}
