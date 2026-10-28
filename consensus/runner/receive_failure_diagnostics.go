package runner

import (
	"fmt"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// ReceiveFailureDiagnosticObserver coordinates one explicit source writer.
// It observes original execution and separately retained failures; it does not
// authorize accepted inputs, functional replay, or physical reconstruction.
// CoreDeclaration must describe the frozen writer header, not mutable defaults.
type ReceiveFailureDiagnosticObserver interface {
	CaptureRun() string
	CoreDeclaration() journal.CoreOptions
	CoreStepObserver
	InboxSourceObserver
	InboxFailureSourceObserver
	transport.ReceiveTransitionObserver
	transport.ReceiveFailureObserver
}

type frozenFailureDiagnostic struct {
	ReceiveFailureDiagnosticObserver
	run string
}

func (f *frozenFailureDiagnostic) CaptureRun() string { return f.run }

// connectFailureDiagnostics installs all related sources together before either
// ledger is constructed. Independent callbacks cannot split this source chain.
func connectFailureDiagnostics(cfg *Config, d *Deps) error {
	observer := d.ReceiveFailureDiagnostics
	if observer == nil {
		return nil
	}
	refuse := func(reason string) error { return fmt.Errorf("runner: receive failure diagnostics: %s", reason) }
	if cfg.ReceiveFailureCache == nil || cfg.ReceiveCache == nil || !cfg.ReceiveCache.KeyWithCode || d.Journal != nil {
		return refuse("explicit failure and code-aware accepted caches with no functional journal are required")
	}
	if cfg.ReceiveFailureCache.Trace != nil || cfg.ReceiveCache.Trace != nil || d.CoreSteps != nil || d.InboxSources != nil || d.InboxFailureSources != nil {
		return refuse("independent cache/core/inbox observers cannot accompany the coordinator")
	}
	run := observer.CaptureRun()
	if run == "" {
		return refuse("writer run is required")
	}
	declaration := observer.CoreDeclaration()
	if err := declaration.ValidateCoreDeclaration(cfg.Core); err != nil {
		return refuse(err.Error())
	}
	if err := declaration.ValidateReceiveFailureDeclaration(cfg.ReceiveFailureCache); err != nil {
		return refuse(err.Error())
	}
	policy := declaration.CachePolicy
	if policy == nil || policy.Validate() != nil || policy.Limits.ReceivePending != cfg.ReceiveCache.Pending || policy.Limits.ReceivePerPeer != cfg.ReceiveCache.PerPeer {
		return refuse("accepted receive limits differ from declaration")
	}
	if declaration.NextHeight.Validate() != nil || (declaration.NextHeight == nil) != (cfg.NextHeight == nil) {
		return refuse("deferred receive declaration differs from runtime")
	}
	if actual, declared := cfg.NextHeight, declaration.NextHeight; actual != nil && (actual.Entries != declared.Entries || actual.Bytes != declared.Bytes || actual.PerPeer != declared.PerPeer || actual.PerSource != declared.PerSource) {
		return refuse("deferred receive limits differ from declaration")
	}
	// Only the namespace is retained as diagnostic metadata. The validated
	// declaration grants no functional permission and is not reread by workers.
	bridge := &frozenFailureDiagnostic{ReceiveFailureDiagnosticObserver: observer, run: run}
	receive, failure := *cfg.ReceiveCache, *cfg.ReceiveFailureCache
	receive.Trace, failure.Trace = bridge, bridge
	cfg.ReceiveCache, cfg.ReceiveFailureCache = &receive, &failure
	d.CoreSteps, d.InboxSources, d.InboxFailureSources = bridge, bridge, bridge
	d.ReceiveFailureDiagnostics = bridge
	return nil
}
