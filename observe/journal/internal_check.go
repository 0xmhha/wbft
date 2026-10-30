package journal

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/bls"
)

// InternalLimits bound retained diagnostic indexes and spans, not decoding
// allocations, the functional queue, signer state or process resource budgets.
type InternalLimits struct {
	Core                                CoreSourceLimits
	Operations, Entries, Outputs, Bytes uint64
}

type InternalCheck struct {
	Status              string `json:"status"`
	Reason              string `json:"reason,omitempty"`
	Scope               string `json:"scope"`
	PhysicalStatus      string `json:"physical_status"`
	ScheduleStatus      string `json:"schedule_status"`
	SignerStatus        string `json:"signer_status"`
	Appended            uint64 `json:"appended,string"`
	Scheduled           uint64 `json:"scheduled,string"`
	OwnMessages         uint64 `json:"own_messages,string"`
	RestoredOwnMessages uint64 `json:"restored_own_messages,string"`
	Popped              uint64 `json:"popped,string"`
	Dispatched          uint64 `json:"dispatched,string"`
	Resets              uint64 `json:"resets,string"`
	Clears              uint64 `json:"clears,string"`
	ClearedInputs       uint64 `json:"cleared_inputs,string"`
	RetainedQueued      uint64 `json:"retained_queued,string"`
	RetainedTaken       uint64 `json:"retained_taken,string"`
}

var ErrInternalSource = errors.New("journal: inconsistent internal input source")

type internalOutputKey struct {
	appCoreKey
	output uint64
}
type internalTaken struct{ appended, selected *InternalRec }

type internalExpected struct {
	source    *CoreStepRec
	scheduled consensus.Input
	broadcast *consensus.Broadcast
	input     []byte
	seen      bool
}

// matchInternalOwn verifies the actual public signature and optional vote seal,
// then removes only the two fields filled by SignVote and compares every other
// encoded message field with the independently recomputed unsigned output.
// This does not re-execute or establish the private validator's signing state.
func matchInternalOwn(in consensus.Input, r *InternalRec, expected *internalExpected) bool {
	m, ok := in.(consensus.Message)
	b := expected.broadcast
	if !ok || b == nil || b.Msg == nil || b.Validators == nil || m.Code != b.Msg.Code || m.Peer != expected.source.CoreSelf || m.RecvMono < 0 || uint64(m.RecvMono) < uint64(expected.source.Entry.Mono) || uint64(m.RecvMono) > r.Mono {
		return false
	}
	domain, err := codec.DecodeRoundChangeDomain(expected.source.DomainBytes)
	if err != nil {
		return false
	}
	outer, err := consensus.RecoverOuterWithDomain(m.Code, m.Payload, domain)
	if err != nil || outer.Source != m.Peer {
		return false
	}
	signed, err := codec.DecodeMessage(m.Code, m.Payload)
	if err != nil {
		return false
	}
	if m.Code == codec.CodePrepare || m.Code == codec.CodeCommit {
		index, found := b.Validators.IndexOf(m.Peer)
		if !found || len(b.SealData) == 0 {
			return false
		}
		key, err := bls.DecodePublicKey(b.Validators.At(index).BLSPublicKey)
		if err != nil {
			return false
		}
		seal, err := bls.DecodeSignature(signed.Seal)
		if err != nil || !bls.Verify(key, b.SealData, seal) {
			return false
		}
	} else if len(signed.Seal) != 0 {
		return false
	}
	signed.Seal, signed.Signature = nil, nil
	unsigned := *b.Msg
	unsigned.Seal, unsigned.Signature = nil, nil
	got, err := codec.EncodeMessage(signed)
	if err != nil {
		return false
	}
	want, err := codec.EncodeMessage(&unsigned)
	return err == nil && bytes.Equal(got, want)
}

// CheckInternalSources binds actual FIFO append/pop/dispatch/clear coordinates
// to independently executed Schedule/Broadcast outputs. It does not assume that
// selection completed a core step or that other input lanes were empty. Missing
// signing-state, restored-prefix and receive-dedup evidence remains unavailable.
func CheckInternalSources(records []Record, limits InternalLimits) (InternalCheck, error) {
	return checkInternalSources(records, limits, false, restoredQueueEvidence{})
}

// CheckRestoredInternalSources explicitly reconstructs original WAL state and
// restore effects before checking the entire observed FIFO. It preserves the
// ordinary restored-prefix guard and never edits markers or invents live steps.
func CheckRestoredInternalSources(records []Record, limits InternalLimits) (InternalCheck, error) {
	restore, seeds, err := reconstructRestoreSources(records, limits.Core)
	report := InternalCheck{Status: "unavailable", Reason: "restore_not_reconstructed", Scope: "internal_queue_on_independent_restored_core", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", SignerStatus: "unavailable"}
	if err != nil || restore.Status != "consistent" {
		if err != nil {
			report.Status = "inconsistent"
		}
		return report, err
	}
	var evidence restoredQueueEvidence
	effects, err := inspectRestoreEffects(records, limits.Core, seeds, func(e restoredQueueEvidence) { evidence = e })
	if err != nil || effects.Status != "consistent" {
		report.Status, report.Reason = effects.Status, "effects_"+effects.Reason
		return report, err
	}
	report, err = checkInternalSources(records, limits, true, evidence)
	report.Scope = "internal_queue_on_independent_restored_core"
	return report, err
}

func checkInternalSources(records []Record, limits InternalLimits, restored bool, evidence restoredQueueEvidence) (InternalCheck, error) {
	report := InternalCheck{Status: "unavailable", Scope: "internal_queue_on_independent_core_outputs", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", SignerStatus: "unavailable"}
	unavailable := func(reason string) (InternalCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (InternalCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrInternalSource, reason)
	}
	if limits.Operations == 0 || limits.Entries == 0 || limits.Outputs == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	expected := map[internalOutputKey]*internalExpected{}
	steps := map[appCoreKey]*CoreStepRec{}
	wanted := map[appCoreKey]bool{}
	resets := map[appCoreKey]bool{}
	stops := map[appCoreKey]bool{}
	var span uint64
	issue := ""
	core, _, err := inspectApplicationCoreOutputs(records, limits.Core, restored, func(writer string, source *CoreStepRec, outputs []consensus.Output) {
		if issue != "" {
			return
		}
		key := appCoreKey{writer, source.EngineRun, source.Step}
		steps[key] = source
		if source.Via == "internal" {
			wanted[key] = false
		}
		if source.InputKind == inputlog.KindStart {
			resets[key] = false
		}
		if source.InputKind == inputlog.KindStop {
			stops[key] = false
		}
		for i, o := range outputs {
			e := &internalExpected{source: source}
			switch v := o.(type) {
			case consensus.Schedule:
				e.scheduled = v.In
				var encodeErr error
				e.input, encodeErr = inputlog.Encode(v.In)
				if encodeErr != nil {
					issue = "internal_output_encoding"
					return
				}
			case consensus.Broadcast:
				e.broadcast = &v
				var encodeErr error
				e.input, encodeErr = inputlog.EncodeOutputs([]consensus.Output{v})
				if encodeErr != nil {
					issue = "internal_output_encoding"
					return
				}
			default:
				continue
			}
			if uint64(len(expected)) >= limits.Outputs {
				issue = "internal_output_limit"
				return
			}
			if uint64(len(e.input)) > limits.Bytes-span {
				issue = "internal_byte_limit"
				return
			}
			span += uint64(len(e.input))
			expected[internalOutputKey{key, uint64(i) + 1}] = e
		}
	})
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	if issue != "" {
		return unavailable(issue)
	}
	for key := range evidence.starts {
		resets[appCoreKey{key.writer, key.engine, 0}] = false
	}
	indexes := map[*InternalRec]int{}
	groups := map[string][]*InternalRec{}
	writer := ""
	var operations uint64
	for index, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindInternal)) {
					return unavailable("internal_source_gap")
				}
			}
		case *InternalRec:
			if operations >= limits.Operations {
				return unavailable("internal_operation_limit")
			}
			if r.Version != InternalSourceVersion {
				return unavailable("internal_version")
			}
			if !validInternalRec(r) {
				return inconsistent("invalid_internal_source")
			}
			if r.Unavailable != "" && (r.Unavailable != "replay_prefix" || evidence.appends[restoredInternalKey{writer, r.EngineRun, r.Sequence}] != r) {
				return unavailable("internal_" + r.Unavailable)
			}
			if writer == "" {
				return unavailable("internal_writer_missing")
			}
			if uint64(len(r.Input)) > limits.Bytes-span {
				return unavailable("internal_byte_limit")
			}
			operations++
			span += uint64(len(r.Input))
			groups[writer] = append(groups[writer], r)
			indexes[r] = index
		}
	}
	if operations == 0 {
		return unavailable("no_internal_sources")
	}
	names := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before validation
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		items := groups[name]
		slices.SortFunc(items, func(a, b *InternalRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		var queue []*InternalRec
		taken := map[uint64]internalTaken{}
		var previous, mono, engine uint64
		for _, r := range items {
			if r.Sequence == previous {
				return inconsistent("internal_sequence_repeated")
			}
			if r.Sequence != previous+1 {
				return unavailable("internal_sequence_gap")
			}
			if r.Mono < mono {
				return inconsistent("internal_time_changed")
			}
			previous, mono = r.Sequence, r.Mono
			if r.Action != "reset" && r.EngineRun != engine {
				return inconsistent("internal_engine_changed")
			}
			if r.Action != "dispatch" && r.Action != "discard" && r.Before != uint64(len(queue)) {
				return inconsistent("internal_queue_state_changed")
			}
			var in consensus.Input
			if r.InputKind != "" {
				in, err = inputlog.Decode(r.InputKind, r.Input, nil)
				if err != nil {
					return inconsistent("internal_input_encoding")
				}
				canonical, e := inputlog.Encode(in)
				if e != nil || !bytes.Equal(canonical, r.Input) {
					return inconsistent("internal_input_encoding")
				}
			}
			switch r.Action {
			case "reset":
				key := appCoreKey{name, r.EngineRun, 1}
				start := steps[key]
				if boundary, ok := evidence.starts[coreSourceRunKey{name, r.EngineRun}]; ok {
					key = appCoreKey{name, r.EngineRun, 0}
					if r.EngineRun != engine+1 || resets[key] || indexes[r] >= boundary.readIndex || indexes[r] >= boundary.ready || r.Mono > boundary.readMono || r.Mono > boundary.installedMono {
						return inconsistent("internal_restore_reset_changed")
					}
				} else {
					if start == nil {
						return unavailable("internal_start_source_missing")
					}
					if r.EngineRun != engine+1 || start.InputKind != inputlog.KindStart || resets[key] || r.Mono > uint64(start.Entry.Mono) {
						return inconsistent("internal_start_source_changed")
					}
				}
				if len(taken) != 0 {
					return unavailable("internal_start_with_undispatched_input")
				}
				resets[key] = true
				report.ClearedInputs += uint64(len(queue))
				queue = nil
				engine = r.EngineRun
				report.Resets++
			case "append":
				if evidence.appends[restoredInternalKey{name, r.EngineRun, r.Sequence}] == r {
					if uint64(len(queue))+uint64(len(taken)) >= limits.Entries {
						return unavailable("internal_entry_limit")
					}
					queue = append(queue, r)
					report.Appended++
					report.RestoredOwnMessages++
				} else {
					key := internalOutputKey{appCoreKey{name, r.EngineRun, r.Step}, r.Output}
					e := expected[key]
					if e == nil {
						return unavailable("internal_output_source_missing")
					}
					if e.seen {
						return inconsistent("internal_output_reused")
					}
					if r.Mono < uint64(e.source.Entry.Mono) || r.Mono > uint64(e.source.Observed.Mono) {
						return inconsistent("internal_output_time_changed")
					}
					if e.scheduled != nil {
						if r.Origin != "schedule" || r.InputKind != inputlog.Kind(e.scheduled) || !bytes.Equal(r.Input, e.input) {
							return inconsistent("internal_scheduled_input_changed")
						}
						report.Scheduled++
					} else {
						if r.Origin != "own" || !matchInternalOwn(in, r, e) {
							return inconsistent("internal_own_input_changed")
						}
						report.OwnMessages++
					}
					if uint64(len(queue))+uint64(len(taken)) >= limits.Entries {
						return unavailable("internal_entry_limit")
					}
					e.seen = true
					queue = append(queue, r)
					report.Appended++
				}
			case "pop":
				if len(queue) == 0 || queue[0].Request != r.Request || queue[0].InputKind != r.InputKind || !bytes.Equal(queue[0].Input, r.Input) {
					return inconsistent("internal_fifo_changed")
				}
				taken[r.Request] = internalTaken{appended: queue[0], selected: r}
				queue = queue[1:]
				report.Popped++
			case "dispatch":
				takenInput := taken[r.Request]
				selected := takenInput.selected
				if selected == nil || selected.InputKind != r.InputKind || !bytes.Equal(selected.Input, r.Input) {
					return inconsistent("internal_selection_source_changed")
				}
				key := appCoreKey{name, r.EngineRun, r.Step}
				source := steps[key]
				if source == nil {
					return unavailable("internal_dispatch_source_missing")
				}
				seen, required := wanted[key]
				if !required || seen || takenInput.appended.EngineRun != r.EngineRun || takenInput.appended.Step >= r.Step || source.InputKind != r.InputKind || !bytes.Equal(source.Input, r.Input) || selected.Mono > uint64(source.Entry.Mono) || r.Mono < uint64(source.Observed.Mono) {
					return inconsistent("internal_dispatch_source_changed")
				}
				wanted[key] = true
				delete(taken, r.Request)
				report.Dispatched++
			case "clear":
				key := appCoreKey{name, r.EngineRun, r.Step}
				source := steps[key]
				if source == nil {
					return unavailable("internal_stop_source_missing")
				}
				if source.InputKind != inputlog.KindStop || stops[key] || r.Mono < uint64(source.Observed.Mono) {
					return inconsistent("internal_stop_source_changed")
				}
				stops[key] = true
				report.ClearedInputs += uint64(len(queue))
				queue = nil
				report.Clears++
			}
			if r.Action != "dispatch" && r.Action != "discard" && r.After != uint64(len(queue)) {
				return inconsistent("internal_result_count_changed")
			}
		}
		report.RetainedQueued += uint64(len(queue))
		report.RetainedTaken += uint64(len(taken))
	}
	for _, e := range expected { //wbft:unordered identical missing-source result
		if !e.seen {
			return unavailable("internal_append_source_missing")
		}
	}
	for _, seen := range wanted { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("internal_dispatch_source_missing")
		}
	}
	for _, seen := range resets { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("internal_reset_source_missing")
		}
	}
	for _, seen := range stops { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("internal_clear_source_missing")
		}
	}
	report.Status, report.Reason = "consistent", ""
	return report, nil
}
