package journal

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// RetrySourceLimits bound independent retained-source inspection. These are
// inspection limits, not runtime retry, cache, payload or resource budgets.
type RetrySourceLimits struct {
	Timers TimerSourceLimits
	Signer privval.SourceLimits
	Writes WriteCacheCheckLimits
}

func (l RetrySourceLimits) Validate() error {
	c, t, s, w := l.Timers.Core, l.Timers, l.Signer, l.Writes
	if c.Records == 0 || c.Runs == 0 || c.Steps == 0 || c.Environments == 0 || c.Outputs == 0 || c.Bytes == 0 ||
		t.Operations == 0 || t.Bindings == 0 || t.Bytes == 0 || s.Lifetimes == 0 || s.Operations == 0 || s.Records == 0 || s.Bytes == 0 ||
		w.Records == 0 || w.Ledgers == 0 || w.Reordered == 0 {
		return fmt.Errorf("journal: retry source inspection limits must all be positive")
	}
	return nil
}

var ErrRoundChangeRetrySource = errors.New("journal: inconsistent retry source")

// RetrySourceCheck verifies conditional owner/timer/signing/WAL/cache links.
// Local I/O, remote delivery, physical persistence and functional cache replay
// remain separate. A ledger-only consistency result cannot satisfy this check.
type RetrySourceCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	Retries        uint64 `json:"retry_outputs,string"`
	Decisions      uint64 `json:"cache_decisions,string"`
}

type retrySourceExpected struct {
	step           *CoreStepRec
	output         consensus.Broadcast
	call           *SignerCallRec
	previous       []byte
	eligible, seen bool
	legacy         bool
	peers          map[types.Address]bool
}

type retrySourceOwner struct {
	writer string
	engine uint64
}

// CheckRoundChangeRetrySources independently recomputes the typed intent;
// diagnostic coordinates select a witness only after that recomputation. It
// also requires actual timer lifetimes, public signing-state verification and
// later original WAL frames for the exact signed bytes and append position.
func CheckRoundChangeRetrySources(records []Record, limits RetrySourceLimits) (RetrySourceCheck, error) {
	report := RetrySourceCheck{Status: "unavailable", Scope: "original_retry_owner_timer_signer_wal_cache_bindings", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (RetrySourceCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (RetrySourceCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrRoundChangeRetrySource, reason)
	}
	if limits.Validate() != nil {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Timers.Core.Records {
		return unavailable("record_limit")
	}
	declared := map[string]RoundChangeRetryOptions{}
	restored, writes := false, false
	run := ""
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			run = r.Run
			policy := RoundChangeRetryOptions{}
			if r.Core.RoundChangeRetry != nil {
				if r.Core.RoundChangeRetry.Validate() != nil {
					return unavailable("unsupported_retry_profile")
				}
				policy = *r.Core.RoundChangeRetry
			}
			if old, ok := declared[run]; ok && old != policy {
				return bad("writer_retry_profile_changed")
			}
			declared[run] = policy
		case *CoreStepRec:
			if r.RetryMaximumMs != 0 && declared[run].Profile == 0 {
				return unavailable("retry_profile_missing")
			}
			restored = restored || r.ReplayedPrefix
		case *WriteCacheRec:
			writes = writes || r.Transition.Retry.Version != 0
		case *GapRec:
			if r.Dropped != 0 {
				return unavailable("retained_source_gap")
			}
		}
	}
	_, seeds, err := reconstructRestoreSources(records, limits.Timers.Core)
	if err != nil {
		return bad("restore_source_changed")
	}
	expected := map[internalOutputKey]*retrySourceExpected{}
	core, _, err := inspectCoreSourceStatesRestored(records, limits.Timers.Core, func(writer string, source *CoreStepRec, outputs []consensus.Output) {
		for i, output := range outputs {
			if b, ok := output.(consensus.Broadcast); ok && b.Msg != nil && b.Msg.Code == codec.CodeRoundChange {
				expected[internalOutputKey{appCoreKey{writer, source.EngineRun, source.Step}, uint64(i) + 1}] = &retrySourceExpected{step: source, output: b}
			}
		}
	}, nil, seeds)
	if err != nil {
		return bad("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	timerCheck := CheckTimerLifecycleSources
	if restored {
		timerCheck = CheckRestoredTimerLifecycleSources
	}
	timers, err := timerCheck(records, limits.Timers)
	if err != nil {
		return bad("timer_" + timers.Reason)
	}
	if timers.Status != "consistent" {
		return unavailable("timer_" + timers.Reason)
	}
	signer, err := checkRestoreSignerCalls(records, limits.Timers.Core, limits.Signer)
	if err != nil {
		return bad("signer_" + signer.Reason)
	}
	if signer.Status != "consistent" {
		return unavailable("signer_" + signer.Reason)
	}
	if writes {
		model, err := CheckWriteCacheTransitions(records, limits.Writes)
		if err != nil {
			return bad("write_" + model.Reason)
		}
		if model.Status != "consistent" {
			return unavailable("write_" + model.Reason)
		}
	}
	groups := map[retrySourceOwner][]*SignerCallRec{}
	signTimes := map[privval.SourceRef]uint64{}
	run = ""
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			run = r.Run
		case *SignerCallRec:
			if r.RequestCode == uint64(codec.CodeRoundChange) && r.Result == "sent" {
				owner := retrySourceOwner{run, r.EngineRun}
				groups[owner] = append(groups[owner], r)
			}
		case *SignerRec:
			signTimes[r.Source.Ref] = r.Mono
		}
	}
	for owner, calls := range groups {
		slices.SortFunc(calls, func(a, b *SignerCallRec) int {
			if c := cmp.Compare(a.Step, b.Step); c != 0 {
				return c
			}
			return cmp.Compare(a.Output, b.Output)
		})
		var previous []byte
		if seed, ok := seeds[coreSourceRunKey(owner)]; ok {
			for _, own := range seed.own {
				if own.Code == uint64(codec.CodeRoundChange) {
					previous = own.Payload
				}
			}
		}
		for _, call := range calls {
			proof := expected[internalOutputKey{appCoreKey{owner.writer, owner.engine, call.Step}, call.Output}]
			if proof == nil || proof.call != nil {
				return bad("own_core_output_missing_or_repeated")
			}
			proof.call, proof.previous = call, previous
			if proof.output.Retry != nil && bytes.Equal(previous, call.Payload) {
				in, err := inputlog.Decode(proof.step.InputKind, proof.step.Input, nil)
				t, ok := in.(consensus.Timeout)
				intent := proof.output.Retry
				if err != nil || !ok || t.Kind != consensus.RetryTimer || t.Gen != intent.Generation || t.View.Cmp(intent.View) != 0 || t.Round.Cmp(intent.View.Round) != 0 ||
					proof.output.Msg.View.Cmp(intent.View) != 0 {
					return bad("recomputed_retry_input_changed")
				}
				// The runner also checks the state after the complete core step.
				// A later view/phase may legitimately take the ordinary route;
				// only a claimed recent-cache exception would contradict it.
				if !proof.step.AfterKnown || proof.step.After.State != consensus.AcceptRequest.String() ||
					proof.step.After.Sequence != intent.View.Sequence.String() || proof.step.After.Round != intent.View.Round.String() {
					previous = call.Payload
					continue
				}
				message, err := codec.DecodeMessage(codec.CodeRoundChange, call.Payload)
				if err != nil {
					return bad("signed_retry_encoding")
				}
				domain, err := codec.DecodeRoundChangeDomain(proof.step.DomainBytes)
				if err != nil {
					return unavailable("round_change_domain_context_unavailable")
				}
				body, err := codec.SigningPayloadWithDomain(message, domain)
				if err != nil || codec.DedupKey(body) != intent.Key {
					return bad("signed_retry_identity")
				}
				author, err := ecdsa.RecoverDataSigner(body, message.Signature)
				if err != nil || author != proof.step.CoreSelf {
					return bad("signed_retry_author")
				}
				proof.eligible = true
				report.Retries++
			}
			previous = call.Payload
		}
	}
	missing := ""
	bind := func(writer string, source transport.RoundChangeRetrySource, code uint64, key, payload types.Hash, peer *types.Address, mono time.Duration) error {
		if source == (transport.RoundChangeRetrySource{}) {
			return nil
		}
		if !validRetrySource(source) {
			return fmt.Errorf("invalid_retry_source")
		}
		if source.EngineRun == 0 || source.Step == 0 || source.Output == 0 {
			missing = "original_retry_owner_missing"
			return nil
		}
		if declared[writer].Profile == 0 {
			missing = "retry_profile_missing"
			return nil
		}
		proof := expected[internalOutputKey{appCoreKey{writer, source.EngineRun, source.Step}, source.Output}]
		if proof == nil || proof.output.Retry == nil || proof.call == nil {
			return fmt.Errorf("retry_core_or_signer_source_changed")
		}
		if len(proof.previous) == 0 {
			missing = "previous_own_source_missing"
			return nil
		}
		if !proof.eligible {
			return fmt.Errorf("retry_owner_not_eligible")
		}
		if mono < 0 || int64(mono) < proof.step.Entry.Mono || int64(mono) > proof.step.Observed.Mono || uint64(mono) > proof.call.Mono {
			return fmt.Errorf("retry_decision_outside_owner_step")
		}
		signedAt, ok := signTimes[proof.call.Source]
		if !ok {
			missing = "original_signer_time_missing"
			return nil
		}
		if uint64(mono) < signedAt {
			return fmt.Errorf("retry_decision_before_signature")
		}
		intent := proof.output.Retry
		if source.Generation != intent.Generation || source.SigningKey != intent.Key || source.Height != intent.View.Sequence.String() || source.Round != intent.View.Round.String() ||
			code != uint64(codec.CodeRoundChange) || key != codec.DedupKey(proof.call.Payload) || payload != sha256.Sum256(proof.call.Payload) {
			return fmt.Errorf("retry_signed_source_changed")
		}
		if proof.output.Validators == nil || !proof.output.Validators.Contains(proof.step.CoreSelf) {
			return fmt.Errorf("retry_self_not_validator")
		}
		if peer != nil && (*peer == proof.step.CoreSelf || !proof.output.Validators.Contains(*peer)) {
			return fmt.Errorf("retry_target_not_validator")
		}
		if peer == nil {
			if proof.seen {
				return fmt.Errorf("retry_gossip_decision_repeated_or_mixed")
			}
			proof.legacy = true
		} else {
			if proof.legacy || proof.peers[*peer] {
				return fmt.Errorf("retry_peer_decision_repeated_or_mixed")
			}
			if proof.peers == nil {
				proof.peers = map[types.Address]bool{}
			}
			proof.peers[*peer] = true
		}
		proof.seen = true
		report.Decisions++
		return nil
	}
	run = ""
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			run = r.Run
		case *CacheRec:
			if r.Retry.Version == 0 {
				continue
			}
			if !validCacheRec(r) {
				return bad("invalid_legacy_retry_operation")
			}
			if err := bind(run, r.Retry, r.Code, r.Key, r.PayloadSHA256, nil, r.Mono); err != nil {
				return bad(err.Error())
			}
			if r.Retry.EngineRun == 0 || declared[run].Profile == 0 {
				continue
			}
			if !r.Available || !slices.Equal(r.Candidates, r.Targets) {
				return bad("legacy_retry_targets_differ_from_candidates")
			}
			for index, peer := range r.Candidates {
				if index > 0 && bytes.Compare(r.Candidates[index-1][:], peer[:]) >= 0 {
					return bad("legacy_retry_candidates_repeated_or_unordered")
				}
				proof := expected[internalOutputKey{appCoreKey{run, r.Retry.EngineRun, r.Retry.Step}, r.Retry.Output}]
				if proof == nil || proof.output.Validators == nil || peer == proof.step.CoreSelf || !proof.output.Validators.Contains(peer) {
					return bad("legacy_retry_candidate_not_validator")
				}
			}
		case *WriteCacheRec:
			t := r.Transition
			if err := bind(run, t.Retry, t.Input.Code, t.Input.Key, t.Input.PayloadSHA256, &t.Input.Peer, r.Mono); err != nil {
				return bad(err.Error())
			}
		}
	}
	if missing != "" {
		return unavailable(missing)
	}
	for _, proof := range expected {
		if proof.eligible && !proof.seen {
			return unavailable("retry_cache_decision_missing")
		}
	}
	if report.Decisions == 0 {
		return unavailable("no_retry_cache_decisions")
	}
	report.Status = "consistent"
	return report, nil
}
