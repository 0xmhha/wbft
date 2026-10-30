package transport

import (
	"bytes"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// RoundChangeRetrySource describes the original owner step. It is detached
// evidence, never authorization to bypass a recent-cache entry.
type RoundChangeRetrySource struct {
	Version, EngineRun, Step, Output, Generation uint64
	Height, Round                                string
	SigningKey                                   types.Hash
}

// RoundChangeRetryRequest is supplied only by the owner after consuming a live
// current-view timer, signing the same message and synchronously recording it.
// Source may be absent; it cannot replace the functional fields or signature.
type RoundChangeRetryRequest struct {
	View            types.View
	Generation      uint64
	SigningKey      types.Hash
	PreviousPayload []byte
	Source          RoundChangeRetrySource
}

// RoundChangeRetryEnabled reports frozen transport configuration, so the
// owning runner can refuse inconsistent policy rather than silently suppress.
func (d *Dedup) RoundChangeRetryEnabled() bool { return d.opt.RoundChangeRetry }

// RoundChangeDomain returns independent frozen retry context storage.
func (d *Dedup) RoundChangeDomain() *types.RoundChangeDomain { return d.opt.RoundChangeDomain.Copy() }

// RetryOwnRoundChange skips only the recent-entry exclusion for an eligible
// attached validator. It never sends directly, clears a cache, bypasses pending
// ownership/capacity or interprets an event cause as functional permission.
func (d *Dedup) RetryOwnRoundChange(vs *validator.Set, payload []byte, request RoundChangeRetryRequest) GossipTargets {
	if !d.opt.RoundChangeRetry || vs == nil || !vs.Contains(d.opt.Self) || request.Generation == 0 ||
		!bytes.Equal(payload, request.PreviousPayload) || CheckOutbound(uint64(codec.CodeRoundChange), payload) != nil {
		return GossipTargets{}
	}
	message, err := codec.DecodeMessage(codec.CodeRoundChange, payload)
	if err != nil || message.View.Cmp(request.View) != 0 {
		return GossipTargets{}
	}
	body, err := codec.SigningPayloadWithDomain(message, d.opt.RoundChangeDomain)
	if err != nil || codec.DedupKey(body) != request.SigningKey {
		return GossipTargets{}
	}
	author, err := ecdsa.RecoverDataSigner(body, message.Signature)
	if err != nil || author != d.opt.Self {
		return GossipTargets{}
	}
	// Owner coordinates are observational. View and key come from the checked
	// functional request, not from caller-provided diagnostic values.
	source := RoundChangeRetrySource{Version: 1, EngineRun: request.Source.EngineRun, Step: request.Source.Step,
		Output: request.Source.Output, Generation: request.Generation, Height: request.View.Sequence.String(),
		Round: request.View.Round.String(), SigningKey: request.SigningKey}
	return d.gossipTargets(vs, uint64(codec.CodeRoundChange), payload, event.CauseRetry, &source)
}
