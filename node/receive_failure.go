package node

import (
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/p2p/transport"
)

// ReceiveFailureCacheConfig bounds separately retained signature/membership
// failures, not process memory, message sizes or verification CPU.
type ReceiveFailureCacheConfig struct {
	Entries uint64
}

// Validate checks only the explicit retained-entry bound.
func (o *ReceiveFailureCacheConfig) Validate() error {
	if o != nil && (o.Entries == 0 || o.Entries > transport.InmemoryMessages) {
		return fmt.Errorf("receive failure entries must be positive and at most %d", transport.InmemoryMessages)
	}
	return nil
}

func freezeReceiveFailureCache(cfg *Config) error {
	if err := cfg.ReceiveFailureCache.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if cfg.ReceiveFailureCache == nil {
		return nil
	}
	if cfg.CachePolicy == nil || !cfg.Journal.Disabled {
		return fmt.Errorf("%w: receive failure cache requires the explicit accepted-input cache policy and disabled functional journal", ErrConfig)
	}
	copyOptions := *cfg.ReceiveFailureCache
	cfg.ReceiveFailureCache = &copyOptions
	return nil
}

func receiveRecoveryLabel(phase consensus.RecoveryFailure) string {
	switch phase {
	case consensus.RecoverySucceeded:
		return "success"
	case consensus.RecoveryDecode:
		return "decode"
	case consensus.RecoveryEncoding:
		return "encoding"
	case consensus.RecoverySignature:
		return "signature"
	case consensus.RecoveryMembership:
		return "membership"
	default:
		return "unknown"
	}
}

func receiveFailureMetricCode(code uint64) string {
	if code < transport.CodeFirst || code > transport.CodeLast {
		return "other"
	}
	return fmt.Sprintf("%#x", code)
}

func (n *Node) connectReceiveFailures(config *runner.Config, deps *runner.Deps) {
	if n.cfg.ReceiveFailureCache == nil {
		return
	}
	entries := n.cfg.ReceiveFailureCache.Entries
	config.ReceiveFailureCache = &transport.ReceiveFailureOptions{Entries: entries}
	if n.diagnostic != nil {
		// connect installed the ordinary source observers first. The explicit
		// coordinator now owns this entire chain, not a mix of callbacks.
		deps.CoreSteps, deps.InboxSources = nil, nil
		config.ReceiveCache.Trace = nil
		deps.ReceiveFailureDiagnostics = n.diagnostic
	}
	n.metrics.Gauge("wbft_cache_receive_failure_limit", "Configured maximum entries in the separate local failure cache; not a heap or CPU bound.").Set(float64(entries))
	checks := n.metrics.Counter("wbft_cache_receive_recovery_total", "Actual receive recovery invocations by result; cache reuse is excluded.", "code", "result")
	deps.ReceiveRecoveryChecked = func(code codec.Code, phase consensus.RecoveryFailure) {
		checks.Inc(receiveFailureMetricCode(uint64(code)), receiveRecoveryLabel(phase))
	}
	hits := n.metrics.Counter("wbft_cache_receive_failure_hits_total", "Reuse of previously failed checks; not new recovery, signer or core acceptance.", "code", "class")
	deps.ReceiveFailureHit = func(code uint64, class transport.ReceiveFailureClass) {
		name := "unknown"
		switch class {
		case transport.ReceiveSignatureFailure:
			name = "signature"
		case transport.ReceiveMembershipFailure:
			name = "membership"
		}
		hits.Inc(receiveFailureMetricCode(code), name)
	}
}
