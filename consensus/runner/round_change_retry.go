package runner

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// retryStepContext is captured by the owner before core.Step. Trace labels and
// a later published snapshot cannot grant this functional timer ownership.
type retryStepContext struct {
	view       types.View
	generation uint64
	live       bool
}

func (r *Runner) roundChangeRetryBefore(q queued, before *consensus.Snapshot, gens [4]uint64) *retryStepContext {
	t, ok := q.in.(consensus.Timeout)
	if r.cfg.Core.RoundChangeRetry == nil || !ok || t.Kind != consensus.RetryTimer {
		return nil
	}
	return &retryStepContext{view: before.View, generation: gens[consensus.RetryTimer], live: r.core.CurrentRoundChangeRetry(t)}
}

// currentOwnRetry requires a successful same-payload signature and is called
// only after the own WAL append-sync. CauseRetry alone never selects it.
func (r *Runner) currentOwnRetry(sc *stepCtx, b consensus.Broadcast, message *codec.Message, payload []byte) bool {
	if r.cfg.Core.RoundChangeRetry == nil || r.d.WAL == nil || sc.retry == nil || !sc.retry.live || b.Retry == nil || message == nil || message.Code != codec.CodeRoundChange {
		return false
	}
	t, ok := sc.q.in.(consensus.Timeout)
	if !ok || t.Kind != consensus.RetryTimer || t.Gen != sc.retry.generation || t.View.Cmp(sc.retry.view) != 0 || t.Round.Cmp(sc.retry.view.Round) != 0 {
		return false
	}
	if b.Retry.Generation != t.Gen || b.Retry.View.Cmp(sc.retry.view) != 0 || message.View.Cmp(sc.retry.view) != 0 {
		return false
	}
	after := r.core.Snapshot()
	if !after.Running || after.State != consensus.AcceptRequest || after.View.Cmp(sc.retry.view) != 0 {
		return false
	}
	body, err := codec.SigningPayload(message, false, nil)
	if err != nil || codec.DedupKey(body) != b.Retry.Key {
		return false
	}
	author, err := ecdsa.RecoverDataSigner(body, message.Signature)
	return err == nil && author == r.cfg.Core.Self && bytes.Equal(r.lastOwn[ownKey{code: uint64(codec.CodeRoundChange)}], payload)
}

// armTimer preserves the original scheduler for disabled policies. A new
// retry cannot publish or install an unrepresentable logical deadline.
func (r *Runner) armTimer(a consensus.ArmTimer, from time.Duration) bool {
	if policy := r.cfg.Core.RoundChangeRetry; policy != nil && a.Kind == consensus.RetryTimer {
		now := r.d.Clock.Mono()
		if policy.MaxIntervalMs == 0 || policy.MaxIntervalMs > uint64(math.MaxInt64/int64(time.Millisecond)) ||
			from < 0 || now < from || a.Duration <= 0 || a.Duration%time.Millisecond != 0 ||
			a.Duration > time.Duration(math.MaxInt64)-from || a.Duration > time.Duration(policy.MaxIntervalMs)*time.Millisecond ||
			a.Retry == nil || a.Retry.MaxIntervalMs != policy.MaxIntervalMs || a.Retry.Exponent > 63 ||
			!a.Retry.Known && (a.Retry.Exponent != 0 || a.Retry.Key != (types.Hash{})) {
			r.halt(fmt.Errorf("runner: invalid round-change retry timer policy or logical deadline"))
			return false
		}
	}
	r.timers.arm(a, from)
	return true
}
