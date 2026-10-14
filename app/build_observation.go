package app

import (
	"sync"

	"github.com/0xmhha/wbft/types"
)

// BuildPhase identifies an application call boundary, independently of core
// requests and proposal acceptance. Observation callbacks must not block.
type BuildPhase uint8

const (
	BuildAssemblyStarted BuildPhase = iota
	BuildCompleted
)

// BuildStatus reports the actual path taken by one application build request.
type BuildStatus string

const (
	BuildSubmitted   BuildStatus = "submitted"
	BuildReplaced    BuildStatus = "replaced"
	BuildHeightLeft  BuildStatus = "height_left"
	BuildStopped     BuildStatus = "stopped"
	BuildUnavailable BuildStatus = "unavailable"
	BuildHeadChanged BuildStatus = "head_changed"
	BuildFailed      BuildStatus = "failed"
)

// BuildObservation is an optional, per-request observer. Copies of a request
// share the same observer: repeated starts/completions are suppressed, without
// changing the builder's queue, timers, cancellation or submission behavior.
// A missing callback remains missing evidence. Callbacks must not re-enter it.
type BuildObservation struct {
	mu                sync.Mutex
	started, finished bool
	report            func(BuildPhase, BuildStatus, types.Hash)
}

func NewBuildObservation(report func(BuildPhase, BuildStatus, types.Hash)) *BuildObservation {
	if report == nil {
		return nil
	}
	return &BuildObservation{report: report}
}

// Started records actual assembly entry, after any requested timer wait.
func (o *BuildObservation) Started() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.started || o.finished {
		return
	}
	o.started = true
	o.report(BuildAssemblyStarted, "", types.Hash{})
}

// Finished records the actual return path. Submitted means the application
// called SubmitProposal; it does not prove that the core accepted the proposal.
func (o *BuildObservation) Finished(status BuildStatus, hash types.Hash) {
	if o == nil {
		return
	}
	switch status {
	case BuildSubmitted, BuildReplaced, BuildHeightLeft, BuildStopped, BuildUnavailable, BuildHeadChanged, BuildFailed:
	default:
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished {
		return
	}
	o.finished = true
	o.report(BuildCompleted, status, hash)
}
