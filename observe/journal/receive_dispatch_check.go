package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type ReceiveDispatchLimits struct {
	Receive           ReceiveSourceLimits
	Selections        SelectionLimits
	Operations, Bytes uint64
}
type ReceiveDispatchCheck struct {
	Status               string `json:"status"`
	Reason               string `json:"reason,omitempty"`
	Scope                string `json:"scope"`
	PhysicalStatus       string `json:"physical_status"`
	ScheduleStatus       string `json:"schedule_status"`
	Prepared             uint64 `json:"prepared,string"`
	Dispatched           uint64 `json:"dispatched,string"`
	DiscardedKnown       uint64 `json:"discarded_known,string"`
	SelfRegistrations    uint64 `json:"self_registrations,string"`
	RetainedPreparations uint64 `json:"retained_preparations,string"`
}

var ErrReceiveDispatchSource = errors.New("journal: inconsistent receive dispatch source")

type receivePreparationFloor struct{ sequence, engine, step uint64 }

type receivePreparationKey struct {
	writer           string
	ledger, sequence uint64
}
type receiveDiscardKey struct {
	writer        string
	engine, inbox uint64
}

// Only the independent checking-ledger/core verifier constructs this evidence.
// Queue inspectors consume it explicitly; they never erase an unavailable marker
// or synthesize a core step for an input the original runner discarded.
type receiveDiscardEvidence struct{ prepare, completion *ReceiveDispatchRec }
type receiveDiscardEvidenceSet map[receiveDiscardKey]receiveDiscardEvidence

func sameReceiveDispatchIdentity(a, b *ReceiveDispatchRec) bool {
	return a.Request == b.Request && a.EngineRun == b.EngineRun && a.BeforeStep == b.BeforeStep && a.Via == b.Via && a.Source == b.Source && a.Scope == b.Scope && a.Decision == b.Decision && a.ContextHash == b.ContextHash && a.Selection == b.Selection && a.InboxRequest == b.InboxRequest && a.InternalRequest == b.InternalRequest && a.Capture == b.Capture && a.Origin == b.Origin && a.StreamRun == b.StreamRun && a.Stream == b.Stream && a.InputKind == b.InputKind && bytes.Equal(a.Input, b.Input)
}

// CheckReceiveDispatchSources verifies original lookup coordinates, independently
// validated external/self registrations, actual dispatch and ticketless Known
// discards. It checks recorded sources, not private signing-state execution,
// restored WAL prefixes, application state, physical I/O or a closed runtime.
func CheckReceiveDispatchSources(records []Record, limits ReceiveDispatchLimits) (ReceiveDispatchCheck, error) {
	return checkReceiveDispatchSources(records, limits, nil)
}

func checkReceiveDispatchSources(records []Record, limits ReceiveDispatchLimits, verified func(receiveDiscardEvidenceSet)) (ReceiveDispatchCheck, error) {
	report := ReceiveDispatchCheck{Status: "unavailable", Scope: "original_receive_lookup_and_actual_input_disposition", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (ReceiveDispatchCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (ReceiveDispatchCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrReceiveDispatchSource, reason)
	}
	if limits.Operations == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	external, err := CheckReceiveSources(records, limits.Receive)
	if err != nil {
		return inconsistent("receive_" + external.Reason)
	}
	if external.Status != "consistent" {
		return unavailable("receive_" + external.Reason)
	}
	internal, err := CheckInternalSources(records, limits.Selections.Internal)
	if err != nil {
		return inconsistent("internal_" + internal.Reason)
	}
	if internal.Status != "consistent" {
		return unavailable("internal_" + internal.Reason)
	}
	snapshots := map[appCoreKey]inboxSourceSnapshot{}
	wanted := map[appCoreKey]bool{}
	core, accepted, err := inspectCoreSourceStates(records, limits.Receive.Core, nil, func(writer string, source *CoreStepRec, snapshot *consensus.Snapshot) {
		key := appCoreKey{writer, source.EngineRun, source.Step}
		snapshots[key] = inboxSourceSnapshot{source, snapshot}
		if source.InputKind == inputlog.KindMessage && (source.Via == "peer" || source.Via == "internal") {
			wanted[key] = false
		}
	})
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	outputs := map[receiveSourceOutputKey]coreSourceAccepted{}
	for _, a := range accepted {
		if a.receiveLedgerRun == "" || a.receiveLedger == 0 {
			continue
		}
		key := receiveSourceOutputKey{receiveSourceCoreKey{a.receiveLedgerRun, a.receiveLedger, a.engine, a.step}, a.output}
		if _, exists := outputs[key]; exists {
			return unavailable("ambiguous_receive_accept_source")
		}
		outputs[key] = a
	}
	lookups := map[receivePreparationKey]*ReceiveCacheRec{}
	selectionsByID := map[finalizeQueueKey]*SelectionRec{}
	internalPops := map[finalizeQueueKey]*InternalRec{}
	inboxTakes := map[finalizeQueueKey]*InboxRec{}
	usedSelections := map[finalizeQueueKey]bool{}
	var selectionCount, internalCount, inboxCount uint64
	groups := map[string][]*ReceiveDispatchRec{}
	registrations := map[receiveSourceOutputKey]bool{}
	registrationFloors := map[receivePreparationKey][]receivePreparationFloor{}
	writer := ""
	var operations, span uint64
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindReceiveDispatch)) {
					return unavailable("receive_dispatch_source_gap")
				}
			}
		case *SelectionRec:
			if selectionCount >= limits.Selections.Operations {
				return unavailable("selection_index_limit")
			}
			selectionCount++
			if r.Action == "select" {
				key := finalizeQueueKey{writer, r.Selection}
				if _, exists := selectionsByID[key]; exists {
					return inconsistent("selection_id_repeated")
				}
				selectionsByID[key] = r
			}
		case *InternalRec:
			if internalCount >= limits.Selections.Internal.Operations {
				return unavailable("internal_index_limit")
			}
			internalCount++
			if r.Action == "pop" {
				key := finalizeQueueKey{writer, r.Sequence}
				if _, exists := internalPops[key]; exists {
					return inconsistent("internal_pop_repeated")
				}
				internalPops[key] = r
			}
		case *InboxRec:
			if inboxCount >= limits.Selections.Inbox.Operations {
				return unavailable("inbox_index_limit")
			}
			inboxCount++
			if r.Action == "take" {
				key := finalizeQueueKey{writer, r.Sequence}
				if _, exists := inboxTakes[key]; exists {
					return inconsistent("inbox_take_repeated")
				}
				inboxTakes[key] = r
			}
		case *ReceiveCacheRec:
			t := r.Transition
			if t.Action == transport.ReceiveCheckPrepare {
				key := receivePreparationKey{writer, t.Ledger, t.Sequence}
				if _, found := lookups[key]; found {
					return inconsistent("receive_lookup_repeated")
				}
				lookups[key] = r
			}
			if t.Action != transport.ReceiveCheckAccept || t.Decision != transport.ReceiveRegistered {
				continue
			}
			key := receiveSourceOutputKey{receiveSourceCoreKey{writer, t.Ledger, t.Source.EngineRun, t.Source.Step}, t.Source.Output}
			a, found := outputs[key]
			if !found {
				return unavailable("receive_registration_core_source_missing")
			}
			if registrations[key] {
				return inconsistent("receive_registration_source_reused")
			}
			registrations[key] = true
			ledgerKey := receivePreparationKey{writer: writer, ledger: t.Ledger}
			registrationFloors[ledgerKey] = append(registrationFloors[ledgerKey], receivePreparationFloor{t.Sequence, a.engine, a.step})
			if t.Source.Via != "self" {
				continue
			}
			state, found := snapshots[appCoreKey{a.writer, a.engine, a.step}]
			if !found {
				return unavailable("self_registration_core_source_missing")
			}
			if state.source.Via != "internal" || t.Source.Via != a.via || t.Input.Peer != state.source.CoreSelf || t.Input != t.Checked || t.Input != a.input.identity || t.Origin != t.CheckedOrigin || t.Origin != a.origin || t.Scope != state.source.ReceiveScopeBefore || !t.ContextKnown || !a.beforeKnown || t.Context != a.before {
				return inconsistent("self_registration_source_changed")
			}
			report.SelfRegistrations++
		case *ReceiveDispatchRec:
			if operations >= limits.Operations {
				return unavailable("receive_dispatch_operation_limit")
			}
			if r.Version != ReceiveDispatchSourceVersion {
				return unavailable("receive_dispatch_version")
			}
			if !validReceiveDispatchRec(r) {
				return inconsistent("invalid_receive_dispatch_source")
			}
			if r.Unavailable != "" {
				return unavailable("receive_dispatch_" + r.Unavailable)
			}
			n := uint64(size(Record{Body: r}))
			if n > limits.Bytes-span {
				return unavailable("receive_dispatch_byte_limit")
			}
			span += n
			if writer == "" {
				return unavailable("receive_dispatch_writer_missing")
			}
			operations++
			groups[writer] = append(groups[writer], r)
		}
	}
	// Each registered ACCEPT necessarily ran before a later lookup in this
	// original ledger. Prefix maxima preserve that causal floor even when clocks
	// are equal; they do not impose order on independent asynchronous observers.
	for _, floors := range registrationFloors { //wbft:unordered each ledger prefix is independent
		slices.SortFunc(floors, func(a, b receivePreparationFloor) int {
			if a.sequence < b.sequence {
				return -1
			}
			if a.sequence > b.sequence {
				return 1
			}
			return 0
		})
		var engine, step uint64
		for i := range floors {
			f := floors[i]
			if f.engine > engine || f.engine == engine && f.step > step {
				engine, step = f.engine, f.step
			}
			floors[i].engine, floors[i].step = engine, step
		}
	}
	if operations == 0 {
		return unavailable("no_receive_dispatch_sources")
	}
	names := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before inspection
		names = append(names, name)
	}
	slices.Sort(names)
	usedLookups := map[receivePreparationKey]bool{}
	discarded := receiveDiscardEvidenceSet{}
	for _, name := range names {
		items := groups[name]
		slices.SortFunc(items, func(a, b *ReceiveDispatchRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		pending := map[uint64]*ReceiveDispatchRec{}
		var previous, mono uint64
		for _, r := range items {
			if r.Sequence == previous {
				return inconsistent("receive_dispatch_sequence_repeated")
			}
			if r.Sequence != previous+1 {
				return unavailable("receive_dispatch_sequence_gap")
			}
			if r.Mono < mono {
				return inconsistent("receive_dispatch_time_changed")
			}
			previous, mono = r.Sequence, r.Mono
			if r.Action == "prepare" {
				key := receivePreparationKey{r.Source.WriterRun, r.Source.Ledger, r.Source.Sequence}
				lookupRecord, found := lookups[key]
				if !found {
					return unavailable("original_preparation_missing")
				}
				lookup := lookupRecord.Transition
				floors := registrationFloors[receivePreparationKey{writer: r.Source.WriterRun, ledger: r.Source.Ledger}]
				i := sort.Search(len(floors), func(i int) bool { return floors[i].sequence >= r.Source.Sequence })
				if i > 0 {
					f := floors[i-1]
					if r.EngineRun < f.engine || r.EngineRun == f.engine && r.BeforeStep < f.step {
						return inconsistent("preparation_precedes_registered_core_accept")
					}
				}

				selectionKey := finalizeQueueKey{name, r.Selection}
				selection := selectionsByID[selectionKey]
				if selection == nil {
					return unavailable("preparation_original_selection_missing")
				}
				if usedSelections[selectionKey] {
					return inconsistent("preparation_selection_reused")
				}
				if selection.EngineRun != r.EngineRun || selection.Step != r.BeforeStep || selection.Lane != r.Via || selection.InputKind != r.InputKind || !bytes.Equal(selection.Input, r.Input) || selection.Mono > r.Mono || uint64(lookupRecord.Mono) > r.Mono {
					return inconsistent("preparation_original_selection_changed")
				}
				usedSelections[selectionKey] = true
				popKey := finalizeQueueKey{name, selection.Source}
				if r.Via == "peer" {
					pop := inboxTakes[popKey]
					if pop == nil {
						return unavailable("preparation_original_inbox_take_missing")
					}
					if pop.EngineRun != r.EngineRun || pop.Request != r.InboxRequest || r.InternalRequest != 0 {
						return inconsistent("preparation_inbox_owner_changed")
					}
				} else {
					pop := internalPops[popKey]
					if pop == nil {
						return unavailable("preparation_original_internal_pop_missing")
					}
					if pop.EngineRun != r.EngineRun || pop.Request != r.InternalRequest || r.InboxRequest != 0 {
						return inconsistent("preparation_internal_owner_changed")
					}
				}
				if usedLookups[key] {
					return inconsistent("original_preparation_reused")
				}
				usedLookups[key] = true
				state, found := snapshots[appCoreKey{name, r.EngineRun, r.BeforeStep}]
				if !found {
					return unavailable("preparation_core_context_missing")
				}
				if !lookup.ScopeActive || lookup.Closed || !lookup.ContextKnown {
					return unavailable("preparation_context_inactive_or_missing")
				}
				context, known, e := coreSourceContext(state.snapshot)
				if e != nil || !known {
					return unavailable("preparation_core_context_unavailable")
				}
				digest, e := InboxSnapshotDigest(state.snapshot)
				if e != nil {
					return unavailable("preparation_context_encoding")
				}
				if digest != r.ContextHash {
					return inconsistent("preparation_snapshot_changed")
				}
				if context != lookup.Context {
					return inconsistent("preparation_lookup_context_changed")
				}
				if state.source.ReceiveLedgerRun != r.Source.WriterRun || state.source.ReceiveLedger != r.Source.Ledger {
					return inconsistent("preparation_ledger_changed")
				}
				// Start publishes the core before its first checking scope is created.
				// The original qualified lookup still proves that new scope's context;
				// a dispatched message must also match the actual next step's scope.
				initialScope := state.source.InputKind == inputlog.KindStart && state.source.ReceiveScopeAfter == 0
				if (!initialScope && state.source.ReceiveScopeAfter != r.Scope) || lookup.Scope != r.Scope {
					return inconsistent("preparation_scope_changed")
				}
				if uint64(lookup.Decision) != r.Decision {
					return inconsistent("preparation_decision_changed")
				}
				if r.Mono < uint64(state.source.Observed.Mono) {
					return inconsistent("preparation_precedes_core_state")
				}
				in, e := inputlog.Decode(r.InputKind, r.Input, nil)
				m, ok := in.(consensus.Message)
				if e != nil || !ok {
					return inconsistent("preparation_input_encoding")
				}
				canonical, e := inputlog.Encode(m)
				if e != nil || !bytes.Equal(canonical, r.Input) {
					return inconsistent("preparation_input_encoding")
				}
				if uint64(m.Code) != lookup.Input.Code || m.Peer != lookup.Input.Peer || codec.DedupKey(m.Payload) != lookup.Input.Key || types.Hash(sha256.Sum256(m.Payload)) != lookup.Input.PayloadSHA256 || r.Origin != lookup.Origin || r.StreamRun != lookup.Input.SessionRun || r.Stream != lookup.Input.Session {
					return inconsistent("preparation_input_identity_changed")
				}
				if r.Via == "peer" && (r.Capture == 0 || r.Origin.CaptureID != r.Capture || r.Origin.WriterRun == "" || r.InboxRequest == 0) {
					return unavailable("preparation_original_frame_missing")
				}
				if r.Via == "internal" && (r.InternalRequest == 0 || m.Peer != state.source.CoreSelf) {
					return inconsistent("preparation_internal_owner_changed")
				}
				pending[r.Request] = r
				report.Prepared++
			} else {
				p := pending[r.Request]
				if p == nil || !sameReceiveDispatchIdentity(p, r) {
					return inconsistent("receive_completion_without_original_preparation")
				}
				if r.Action == "discard" {
					key := receiveDiscardKey{name, r.EngineRun, r.InboxRequest}
					if _, exists := discarded[key]; exists {
						return inconsistent("known_discard_source_reused")
					}
					if r.Decision != uint64(transport.ReceiveKnown) || r.Via != "peer" {
						return inconsistent("discard_without_known_lookup")
					}
					discarded[key] = receiveDiscardEvidence{p, r}
					report.DiscardedKnown++
				} else {
					key := appCoreKey{name, r.EngineRun, r.Step}
					state, found := snapshots[key]
					if !found {
						return unavailable("receive_completion_core_source_missing")
					}
					seen, required := wanted[key]
					if !required || seen || state.source.Via != r.Via || state.source.InputKind != r.InputKind || !bytes.Equal(state.source.Input, r.Input) || state.source.Origin != r.Origin || state.source.StreamRun != r.StreamRun || state.source.Stream != r.Stream || state.source.ReceiveLedgerRun != r.Source.WriterRun || state.source.ReceiveLedger != r.Source.Ledger || state.source.ReceiveScopeBefore != r.Scope || p.Mono > uint64(state.source.Entry.Mono) || r.Mono < uint64(state.source.Observed.Mono) {
						return inconsistent("receive_completion_core_input_changed")
					}
					wanted[key] = true
					report.Dispatched++
				}
				delete(pending, r.Request)
			}
		}
		report.RetainedPreparations += uint64(len(pending))
	}
	for _, seen := range wanted { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("core_message_without_original_prepare")
		}
	}
	selections, err := checkInputSelections(records, limits.Selections, discarded)
	if err != nil {
		return inconsistent("selection_" + selections.Reason)
	}
	if selections.Status != "consistent" {
		return unavailable("selection_" + selections.Reason)
	}
	if selections.DiscardedKnown != report.DiscardedKnown {
		return inconsistent("known_discard_selection_count_changed")
	}
	report.Status, report.Reason = "consistent", ""
	if verified != nil {
		verified(discarded)
	}
	return report, nil
}
