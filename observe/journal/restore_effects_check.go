package journal

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// RestoreEffectsCheck covers computed restore timers, replay-owned FIFO appends
// and their first actual live dispatch. Other queue and scheduling operations,
// signer state, application execution and physical effects remain separate.
type RestoreEffectsCheck struct {
	Status, Reason, Scope                      string
	Arms, InternalAppends, FirstLiveDispatches uint64
}
type restoreTimerKey struct {
	coreSourceRunKey
	kind consensus.TimerKind
}
type restoreTimerExpected struct {
	seed     restoredCoreSeed
	input    []byte
	duration time.Duration
	seen     bool
	arm      *TimerRec
	queued   bool
	expiry   *TimerRec
}
type restoreInternalExpected struct {
	seed     restoredCoreSeed
	message  consensus.Message
	appended *InternalRec
	index    int
}

// CheckRestoredBoundarySources never feeds observed mutations to a core. Seeds
// come only from the independently reconstructed original readable prefix.
func CheckRestoredBoundarySources(records []Record, limits CoreSourceLimits) (RestoreCheck, CoreSourceCheck, RestoreEffectsCheck, error) {
	return checkRestoredBoundarySourcesBudget(records, limits, nil, 0)
}

func checkRestoredBoundarySourcesBudget(records []Record, limits CoreSourceLimits, budget *originBudget, span uint64) (RestoreCheck, CoreSourceCheck, RestoreEffectsCheck, error) {
	if err := budget.pass(span, 16); err != nil {
		return RestoreCheck{Status: "unavailable", Reason: err.Error()}, CoreSourceCheck{}, RestoreEffectsCheck{}, nil
	}
	restore, seeds, err := reconstructRestoreSourcesBudget(records, limits, budget)
	effects := RestoreEffectsCheck{Status: "unavailable", Scope: "restore_timer_and_internal_first_live_bindings"}
	if err != nil || restore.Status != "consistent" {
		effects.Reason = "restore_not_reconstructed"
		return restore, CoreSourceCheck{Status: "unavailable", Reason: effects.Reason}, effects, err
	}
	// Inspect the initial derived seed before the live core inspector advances it.
	if err := budget.pass(span, 16); err != nil {
		effects.Reason = err.Error()
		return restore, CoreSourceCheck{Status: "unavailable", Reason: effects.Reason}, effects, nil
	}
	effects, err = checkRestoreEffects(records, limits, seeds)
	if err != nil || effects.Status != "consistent" {
		return restore, CoreSourceCheck{Status: "unavailable", Reason: "restore_effects_not_reconstructed"}, effects, err
	}
	// This call builds fresh independent seeds. Mutable model state is never
	// shared between separate inspections or exposed as a caller certificate.
	restore, core, err := checkRestoredCoreSourcesBudget(records, limits, budget, span)
	return restore, core, effects, err
}

type restoredQueueStart struct {
	readIndex, ready        int
	readMono, installedMono uint64
}
type restoredTimerSourceKey struct {
	writer           string
	engine, sequence uint64
}

type restoredInternalKey struct {
	writer           string
	engine, sequence uint64
}
type restoredQueueEvidence struct {
	starts  map[coreSourceRunKey]restoredQueueStart
	appends map[restoredInternalKey]*InternalRec
	timers  map[restoredTimerSourceKey]*TimerRec
}

func checkRestoreEffects(records []Record, limits CoreSourceLimits, seeds map[coreSourceRunKey]restoredCoreSeed) (RestoreEffectsCheck, error) {
	return inspectRestoreEffects(records, limits, seeds, nil)
}

func inspectRestoreEffects(records []Record, limits CoreSourceLimits, seeds map[coreSourceRunKey]restoredCoreSeed, verified func(restoredQueueEvidence)) (RestoreEffectsCheck, error) {
	report := RestoreEffectsCheck{Status: "unavailable", Scope: "restore_timer_and_internal_first_live_bindings"}
	unavailable := func(reason string) (RestoreEffectsCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (RestoreEffectsCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrRestoreSource, reason)
	}
	timers := map[restoreTimerKey]*restoreTimerExpected{}
	internal := map[coreSourceRunKey][]*restoreInternalExpected{}
	seenLive := map[coreSourceRunKey]bool{}
	var usedBytes, bindings uint64
	charge := func(n uint64) bool {
		if n > limits.Bytes-usedBytes || bindings >= limits.Outputs {
			return false
		}
		usedBytes += n
		bindings++
		return true
	}
	for key, seed := range seeds {
		for kind, t := range seed.timers {
			if t == nil {
				continue
			}
			input, e := inputlog.Encode(consensus.Timeout{Kind: t.Kind, View: t.View, Round: t.Round, Gen: t.Gen, Msg: t.Msg})
			if e != nil {
				return unavailable("restore_timer_encoding")
			}
			if !charge(uint64(len(input))) {
				return unavailable("restore_binding_limit")
			}
			timers[restoreTimerKey{key, consensus.TimerKind(kind)}] = &restoreTimerExpected{seed: seed, input: input, duration: t.Duration}
		}
		snap := seed.model.state.Snapshot()
		vars := seed.model.state.Vars()
		if vars == nil {
			continue
		}
		for _, own := range seed.own {
			code := codec.Code(own.Code)
			if code != codec.CodePrepare && code != codec.CodeCommit && code != codec.CodeRoundChange {
				continue
			}
			m, e := codec.DecodeMessage(code, own.Payload)
			if e != nil {
				return bad("restore_own_decode_changed")
			}
			if m.View.Sequence.Cmp(snap.View.Sequence) != 0 || m.View.Round.Cmp(snap.View.Round) != 0 || restoreOwnCounted(vars, code, seed.config.self) {
				continue
			}
			if !charge(uint64(len(own.Payload))) {
				return unavailable("restore_binding_limit")
			}
			internal[key] = append(internal[key], &restoreInternalExpected{seed: seed, message: consensus.Message{Code: code, Payload: own.Payload, Peer: seed.config.self}})
		}
	}
	// Own codes are in the independently checked canonical ascending order,
	// matching the runtime's replay resend order. No timestamp sorts this stream.
	writer := ""
	declarations := map[string]uint64{}
	counts := map[coreSourceRunKey]int{}
	type indexedInternal struct {
		record *InternalRec
		index  int
	}
	type internalKey struct {
		writer          string
		engine, request uint64
	}
	indexed := map[internalKey][]indexedInternal{}
	for i, rec := range records {
		switch r := rec.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *InternalRec:
			key := internalKey{writer, r.EngineRun, r.Request}
			indexed[key] = append(indexed[key], indexedInternal{r, i})
		}
	}
	writer = ""
	var operations uint64
	for position, rec := range records {
		switch r := rec.Body.(type) {
		case *SegmentRec:
			writer = r.Run
			declarations[writer] = r.Core.TimerTrace
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindTimer) || k.Kind == uint64(KindInternal)) {
					return unavailable("restore_effect_source_gap")
				}
			}
		case *TimerRec:
			operations++
			if operations > limits.Records {
				return unavailable("restore_operation_limit")
			}
			if r.Source != "restore" {
				continue
			}
			if !charge(uint64(len(r.Input))) {
				return unavailable("restore_binding_limit")
			}
			if declarations[writer] != TimerTraceVersion {
				return unavailable("restore_timer_trace_not_declared")
			}
			if !validTimerRec(r) {
				return bad("invalid_restore_timer")
			}
			if r.Action != "arm" && r.Action != "queued" {
				return bad("unexpected_restore_timer_operation")
			}
			in, e := inputlog.Decode(inputlog.KindTimeout, r.Input, nil)
			if e != nil {
				return bad("invalid_restore_timeout")
			}
			timeout := in.(consensus.Timeout)
			proof := timers[restoreTimerKey{coreSourceRunKey{writer, r.EngineRun}, timeout.Kind}]
			if proof == nil {
				return bad("restore_timer_owner_changed")
			}
			// An actual callback retains its original arm owner, including the
			// restore source tag. It can arrive after installation; it is not
			// another restore-time arm. Bind only this retained expiry to its
			// verified arm, without claiming a complete scheduler lifecycle.
			if r.Action == "queued" {
				arm := proof.arm
				if arm == nil || proof.queued || r.Sequence <= arm.Sequence || r.Step != 0 || r.Output != 0 || r.ArmEngineRun != arm.ArmEngineRun || r.ArmStep != 0 || r.ArmOutput != 0 || !bytes.Equal(r.Input, proof.input) || r.EntryMono != arm.EntryMono || r.Deadline != arm.Deadline || r.Mono < arm.Mono || r.Mono < r.Deadline {
					return bad("restore_timer_expiry_changed")
				}
				proof.queued = true
				proof.expiry = r
				continue
			}
			if proof.seen || r.Step != 0 || r.Output != 0 || r.ArmEngineRun != r.EngineRun || r.ArmStep != 0 || r.ArmOutput != 0 || !bytes.Equal(r.Input, proof.input) {
				return bad("restore_timer_value_changed")
			}
			if position <= proof.seed.readIndex || position >= proof.seed.ready || r.EntryMono < time.Duration(proof.seed.read.Mono) || r.Mono > time.Duration(proof.seed.installed.Mono) {
				return bad("restore_timer_outside_installation")
			}
			if proof.duration > 0 && r.EntryMono > time.Duration(math.MaxInt64)-proof.duration || proof.duration < 0 && r.EntryMono < time.Duration(math.MinInt64)-proof.duration {
				return unavailable("restore_deadline_range")
			}
			if r.Deadline != r.EntryMono+proof.duration {
				return bad("restore_timer_deadline_changed")
			}
			proof.seen = true
			proof.arm = r
			report.Arms++
		case *InternalRec:
			operations++
			if operations > limits.Records {
				return unavailable("restore_operation_limit")
			}
			if r.Action != "append" || r.Origin != "replay" {
				continue
			}
			if !charge(uint64(len(r.Input))) {
				return unavailable("restore_binding_limit")
			}
			if !validInternalRec(r) || r.Unavailable != "replay_prefix" {
				return bad("invalid_restore_internal")
			}
			key := coreSourceRunKey{writer, r.EngineRun}
			i := counts[key]
			if i >= len(internal[key]) {
				return bad("unexpected_restore_internal")
			}
			proof := internal[key][i]
			counts[key]++
			in, e := inputlog.Decode(r.InputKind, r.Input, nil)
			if e != nil {
				return bad("restore_internal_input_changed")
			}
			m, ok := in.(consensus.Message)
			if !ok || m.Code != proof.message.Code || m.Peer != proof.message.Peer || !bytes.Equal(m.Payload, proof.message.Payload) || m.RecvMono < 0 || uint64(m.RecvMono) > r.Mono {
				return bad("restore_internal_input_changed")
			}
			if position <= proof.seed.readIndex || position >= proof.seed.ready || r.Mono < proof.seed.read.Mono || r.Mono > proof.seed.installed.Mono {
				return bad("restore_internal_outside_installation")
			}
			proof.appended, proof.index = r, position
			report.InternalAppends++
		case *CoreStepRec:
			key := coreSourceRunKey{writer, r.EngineRun}
			seed, ok := seeds[key]
			if !ok || seenLive[key] {
				continue
			}
			seenLive[key] = true
			if position <= seed.ready || r.Step != seed.model.next || !r.ReplayedPrefix {
				return bad("restored_first_live_owner_changed")
			}
			if len(internal[key]) == 0 {
				continue
			}
			proof := internal[key][0]
			if proof.appended == nil {
				return unavailable("restore_internal_append_missing")
			}
			if r.Via != "internal" || r.InputKind != proof.appended.InputKind || !bytes.Equal(r.Input, proof.appended.Input) {
				return bad("restore_internal_first_live_changed")
			}
			var popped, dispatched bool
			// All internal operations run synchronously on the consensus loop.
			// Keep their original indexes; never infer order from equal clocks.
			for _, event := range indexed[internalKey{writer, r.EngineRun, proof.appended.Request}] {
				ir, j := event.record, event.index
				if ir.Action == "pop" {
					if popped || j <= proof.index || j >= position || !validInternalRec(ir) || !bytes.Equal(ir.Input, r.Input) || ir.Mono > uint64(r.Entry.Mono) {
						return bad("restore_internal_pop_changed")
					}
					popped = true
				}
				if ir.Action == "dispatch" {
					if dispatched || j <= position || ir.Step != r.Step || !validInternalRec(ir) || !bytes.Equal(ir.Input, r.Input) || ir.Mono < uint64(r.Observed.Mono) {
						return bad("restore_internal_dispatch_changed")
					}
					dispatched = true
				}
			}
			if !popped || !dispatched {
				return unavailable("restore_internal_first_live_binding_missing")
			}
			report.FirstLiveDispatches++
		}
	}
	for _, proof := range timers {
		if !proof.seen {
			return unavailable("restore_timer_arm_missing")
		}
	}
	for key, expected := range internal {
		if counts[key] != len(expected) {
			return unavailable("restore_internal_append_missing")
		}
	}
	for key := range seeds {
		if !seenLive[key] {
			return unavailable("restored_first_live_source_missing")
		}
	}
	if len(seeds) == 0 {
		return unavailable("no_restored_prefix")
	}
	if verified != nil {
		evidence := restoredQueueEvidence{starts: map[coreSourceRunKey]restoredQueueStart{}, appends: map[restoredInternalKey]*InternalRec{}, timers: map[restoredTimerSourceKey]*TimerRec{}}
		for key, seed := range seeds { //wbft:unordered independent keyed evidence collection commutes
			evidence.starts[key] = restoredQueueStart{seed.readIndex, seed.ready, seed.read.Mono, seed.installed.Mono}
		}
		for key, items := range internal { //wbft:unordered independent keyed evidence collection commutes
			for _, item := range items {
				if item.appended != nil {
					evidence.appends[restoredInternalKey{key.writer, key.engine, item.appended.Sequence}] = item.appended
				}
			}
		}
		for key, proof := range timers { //wbft:unordered independent keyed timer evidence collection commutes
			if proof.arm != nil {
				evidence.timers[restoredTimerSourceKey{key.writer, key.engine, proof.arm.Sequence}] = proof.arm
			}
			if proof.expiry != nil {
				evidence.timers[restoredTimerSourceKey{key.writer, key.engine, proof.expiry.Sequence}] = proof.expiry
			}
		}
		verified(evidence)
	}
	report.Status = "consistent"
	return report, nil
}

func restoreOwnCounted(vars *consensus.Vars, code codec.Code, self types.Address) bool {
	switch code {
	case codec.CodePrepare:
		return slices.Contains(vars.Prepares, self)
	case codec.CodeCommit:
		return slices.Contains(vars.Commits, self)
	case codec.CodeRoundChange:
		for _, rc := range vars.RoundChanges {
			if slices.Contains(rc.Sources, self) {
				return true
			}
		}
	}
	return false
}
