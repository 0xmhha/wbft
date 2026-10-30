package journal

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

// SelectionLimits bound each prerequisite inspection, source-state indexes and
// selected-input spans. They do not bound runtime queues or process resources.
type SelectionLimits struct {
	Internal                   InternalLimits
	App                        AppQueueLimits
	Timer                      TimerSourceLimits
	Inbox                      InboxLimits
	Operations, Sources, Bytes uint64
}
type SelectionCheck struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Scope            string `json:"scope"`
	PhysicalStatus   string `json:"physical_status"`
	ScheduleStatus   string `json:"schedule_status"`
	Attempts         uint64 `json:"attempts,string"`
	Empty            uint64 `json:"empty,string"`
	Selected         uint64 `json:"selected,string"`
	RandomChoices    uint64 `json:"random_choices,string"`
	Dispatched       uint64 `json:"dispatched,string"`
	DiscardedKnown   uint64 `json:"discarded_known,string"`
	RetainedSelected uint64 `json:"retained_selected,string"`
}

var ErrInputSelectionSource = errors.New("journal: inconsistent input selection source")

type selectionLaneKey struct{ writer, lane string }
type selectionMutation struct {
	serial                          bool // original loop mutation necessarily completed with its core step
	sequence, mono, engine, step    uint64
	request, ownerEngine, ownerStep uint64
	action, inputKind               string
	input                           []byte
	after                           uint64
}
type selectionState struct {
	ready bool
	mono  uint64
}
type selectionFloor struct{ engine, step, sequence uint64 }

type selectionLane struct {
	floors []selectionFloor
	states map[uint64]selectionState
	pops   map[uint64]*selectionMutation
	used   map[uint64]bool
	last   uint64
}

// minimumSequence excludes reads before mutations that a completed source
// step necessarily finished. It orders equal-time evidence without imposing a
// total order on independent asynchronous callbacks or other lane mutexes.
func (l *selectionLane) minimumSequence(engine, step uint64) uint64 {
	i := sort.Search(len(l.floors), func(i int) bool { f := l.floors[i]; return f.engine > engine || f.engine == engine && f.step > step })
	if i == 0 {
		return 0
	}
	return l.floors[i-1].sequence
}

// selectedLane checks original short-circuit priority without inventing probes
// of later lanes. The two timed queues are independently sampled, not atomic.
func selectedLane(r *SelectionRec) (string, bool) {
	skipped := func(p InputProbe) bool { return p.State == "not_probed" }
	if r.Internal.State == "ready" {
		return "internal", skipped(r.App) && skipped(r.Timer) && skipped(r.Inbox) && r.NextHeight == "not_probed" && r.Random == 0 && r.Choice == 0
	}
	if r.Internal.State != "empty" {
		return "", false
	}
	if r.App.State == "ready" {
		return "app", skipped(r.Timer) && skipped(r.Inbox) && r.NextHeight == "not_probed" && r.Random == 0 && r.Choice == 0
	}
	if r.App.State != "empty" || r.NextHeight != "disabled" || skipped(r.Timer) || skipped(r.Inbox) {
		return "", false
	}
	timer, peer := r.Timer.State == "ready", r.Inbox.State == "ready"
	if timer && peer {
		if r.Random != 1 {
			return "", false
		}
		if r.Choice == 0 {
			return "timer", true
		}
		return "peer", true
	}
	if r.Random != 0 || r.Choice != 0 {
		return "", false
	}
	if timer {
		return "timer", true
	}
	if peer {
		return "peer", true
	}
	return "none", true
}

// CheckInputSelections validates original conditional probes against separately
// reconstructed lanes, the original one-choice result, each actual dequeue and
// its eventual core dispatch. Consistency does not close physical execution,
// random generator state, signer state, application execution or a WAL prefix.
func CheckInputSelections(records []Record, limits SelectionLimits) (SelectionCheck, error) {
	return checkInputSelections(records, limits, nil)
}

func checkInputSelections(records []Record, limits SelectionLimits, discarded receiveDiscardEvidenceSet) (SelectionCheck, error) {
	return inspectInputSelections(records, limits, discarded, false)
}

func inspectInputSelections(records []Record, limits SelectionLimits, discarded receiveDiscardEvidenceSet, restored bool) (SelectionCheck, error) {
	return inspectInputSelectionReports(records, limits, discarded, restored, nil)
}

func inspectInputSelectionReports(records []Record, limits SelectionLimits, discarded receiveDiscardEvidenceSet, restored bool, checkedInbox func(InboxCheck)) (SelectionCheck, error) {
	consumed := map[receiveDiscardKey]bool{}
	bySelection := map[finalizeQueueKey]receiveDiscardKey{}
	for key, evidence := range discarded { //wbft:unordered duplicate gives identical error
		selection := finalizeQueueKey{key.writer, evidence.prepare.Selection}
		if _, exists := bySelection[selection]; exists {
			return SelectionCheck{Status: "inconsistent", Reason: "known_discard_selection_reused"}, ErrInputSelectionSource
		}
		bySelection[selection] = key
	}
	report := SelectionCheck{Status: "unavailable", Scope: "conditional_input_probes_and_original_dequeues", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (SelectionCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (SelectionCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrInputSelectionSource, reason)
	}
	if limits.Operations == 0 || limits.Sources == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	internalCheck := CheckInternalSources
	if restored {
		internalCheck = CheckRestoredInternalSources
	}
	internal, err := internalCheck(records, limits.Internal)
	if err != nil {
		return inconsistent("internal_" + internal.Reason)
	}
	if internal.Status != "consistent" {
		return unavailable("internal_" + internal.Reason)
	}
	app, err := checkAppQueueSources(records, limits.App, restored)
	if err != nil {
		return inconsistent("app_" + app.Reason)
	}
	if app.Status != "consistent" {
		return unavailable("app_" + app.Reason)
	}
	timerCheck := CheckTimerLifecycleSources
	if restored {
		timerCheck = CheckRestoredTimerLifecycleSources
	}
	timer, err := timerCheck(records, limits.Timer)
	if err != nil {
		return inconsistent("timer_" + timer.Reason)
	}
	if timer.Status != "consistent" {
		return unavailable("timer_" + timer.Reason)
	}
	inbox, err := inspectInboxSources(records, limits.Inbox, discarded, restored)
	if checkedInbox != nil {
		checkedInbox(inbox)
	}
	if err != nil {
		return inconsistent("inbox_" + inbox.Reason)
	}
	if inbox.Status != "consistent" {
		return unavailable("inbox_" + inbox.Reason)
	}
	// The first post-restore probe follows a verified WAL installation, not a
	// synthetic live Start step. Keep its original index and monotonic boundary.
	installed := map[appCoreKey]restoredQueueStart{}
	if restored {
		restore, seeds, e := reconstructRestoreSources(records, limits.Internal.Core)
		if e != nil {
			return inconsistent("restore_" + restore.Reason)
		}
		if restore.Status != "consistent" {
			return unavailable("restore_" + restore.Reason)
		}
		for key, seed := range seeds { //wbft:unordered independent installation indexes commute
			installed[appCoreKey{key.writer, key.engine, seed.installed.Steps}] = restoredQueueStart{seed.readIndex, seed.ready, seed.read.Mono, seed.installed.Mono}
		}
	}
	indexes := map[*SelectionRec]int{}
	mutations := map[selectionLaneKey][]*selectionMutation{}
	groups := map[string][]*SelectionRec{}
	steps := map[appCoreKey]*CoreStepRec{}
	wanted := map[appCoreKey]bool{}
	captures := map[finalizeQueueKey]*InboxRec{}
	internalAppends := map[finalizeQueueKey]*InternalRec{}
	inboxChecks := map[finalizeQueueKey]*InboxRec{}
	var operations, sources, span uint64
	writer := ""
	charge := func(n int) bool {
		if uint64(n) > limits.Bytes-span {
			return false
		}
		span += uint64(n)
		return true
	}
	for index, record := range records {
		var mutation *selectionMutation
		lane := ""
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *CoreStepRec:
			key := appCoreKey{writer, r.EngineRun, r.Step}
			steps[key] = r
			switch r.Via {
			case "internal", "app", "timer", "peer":
				wanted[key] = false
			}
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindSelection)) {
					return unavailable("selection_source_gap")
				}
			}
		case *SelectionRec:
			indexes[r] = index
			if operations >= limits.Operations {
				return unavailable("selection_operation_limit")
			}
			if r.Version != SelectionSourceVersion {
				return unavailable("selection_version")
			}
			if !validSelectionRec(r) {
				return inconsistent("invalid_selection_source")
			}
			if r.Unavailable != "" {
				_, certified := bySelection[finalizeQueueKey{writer, r.Selection}]
				if r.Action != "discard" || r.Unavailable != "dispatch_deduplicated" || !certified {
					return unavailable("selection_" + r.Unavailable)
				}
			}
			if writer == "" {
				return unavailable("selection_writer_missing")
			}
			if !charge(len(r.Input)) {
				return unavailable("selection_byte_limit")
			}
			operations++
			groups[writer] = append(groups[writer], r)
		case *InternalRec:
			if r.Action == "append" {
				internalAppends[finalizeQueueKey{writer, r.Request}] = r
			}
			lane = "internal"
			mutation = &selectionMutation{sequence: r.Sequence, mono: r.Mono, engine: r.EngineRun, step: r.Step, action: r.Action, inputKind: r.InputKind, input: r.Input, after: r.After, request: r.Request, serial: r.Action != "pop" && r.Action != "discard"}
		case *AppQueueRec:
			lane = "app"
			mutation = &selectionMutation{sequence: r.Sequence, mono: uint64(r.Mono), engine: r.EngineRun, step: r.Step, action: r.Action, inputKind: r.InputKind, input: r.Input, after: r.After, serial: r.EngineRun > 0 && r.Step > 0}
		case *TimerRec:
			lane = "timer"
			mutation = &selectionMutation{sequence: r.Sequence, mono: uint64(r.Mono), engine: r.EngineRun, step: r.Step, action: r.Action, inputKind: inputlog.KindTimeout, input: r.Input, ownerEngine: r.ArmEngineRun, ownerStep: r.ArmStep, serial: r.Action != "queued" && (r.Source == "core" || r.Source == "dequeue" || r.Source == "lifecycle")}
		case *InboxRec:
			lane = "peer"
			mutation = &selectionMutation{sequence: r.Sequence, mono: r.Mono, engine: r.EngineRun, step: r.Step, action: r.Action, serial: r.Action == "dispatch" || r.Action == "clear"}
			if r.Action == "append" {
				captures[finalizeQueueKey{writer, r.Request}] = r
			}
			if r.Action == "check" {
				inboxChecks[finalizeQueueKey{writer, r.Request}] = r
			}
			if r.Action == "check" && r.Result == "insert" {
				mutation.action = "insert"
			}
			// Inputs are resolved only after all original source appends are indexed.
			if r.Action == "take" {
				mutation.after = r.Request
				mutation.inputKind = inputlog.KindMessage
			}
		}
		if mutation != nil {
			if sources >= limits.Sources {
				return unavailable("selection_source_index_limit")
			}
			sources++
			mutations[selectionLaneKey{writer, lane}] = append(mutations[selectionLaneKey{writer, lane}], mutation)
		}
	}
	if operations == 0 {
		return unavailable("no_selection_sources")
	}
	lanes := map[selectionLaneKey]*selectionLane{}
	keys := make([]selectionLaneKey, 0, len(mutations))
	for key := range mutations { //wbft:unordered sorted before validation
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b selectionLaneKey) int {
		if a.writer < b.writer {
			return -1
		}
		if a.writer > b.writer {
			return 1
		}
		if a.lane < b.lane {
			return -1
		}
		if a.lane > b.lane {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		items := mutations[key]
		slices.SortFunc(items, func(a, b *selectionMutation) int {
			if a.sequence < b.sequence {
				return -1
			}
			if a.sequence > b.sequence {
				return 1
			}
			return 0
		})
		lane := &selectionLane{states: map[uint64]selectionState{0: {}}, pops: map[uint64]*selectionMutation{}, used: map[uint64]bool{}}
		var count uint64
		for _, m := range items {
			switch key.lane {
			case "internal":
				if m.action == "pop" {
					a := internalAppends[finalizeQueueKey{key.writer, m.request}]
					if a == nil {
						return unavailable("selection_internal_append_missing")
					}
					m.ownerEngine, m.ownerStep = a.EngineRun, a.Step
				}
				if m.action != "dispatch" && m.action != "discard" {
					count = m.after
				}
			case "app":
				count = m.after
			case "timer":
				switch m.action {
				case "queued":
					count++
				case "pop":
					if count == 0 {
						return inconsistent("timer_probe_index_underflow")
					}
					count--
				case "clear":
					count = 0
				}
			case "peer":
				switch m.action {
				case "insert":
					count++
				case "take":
					if count == 0 {
						return inconsistent("inbox_probe_index_underflow")
					}
					count--
					check := inboxChecks[finalizeQueueKey{key.writer, m.after}]
					if check == nil {
						return unavailable("selection_inbox_check_missing")
					}
					m.ownerEngine, m.ownerStep = check.SnapshotEngine, check.SnapshotStep
					a := captures[finalizeQueueKey{key.writer, m.after}]
					if a == nil {
						return unavailable("selection_capture_source_missing")
					}
					m.input, err = inputlog.Encode(consensus.Message{Code: codec.Code(a.Code), Payload: a.Payload, Peer: a.Peer, RecvMono: time.Duration(a.RecvMono)})
					if err != nil {
						return unavailable("selection_input_encoding")
					}
				case "clear":
					count = 0
				}
			}
			lane.states[m.sequence] = selectionState{count > 0, m.mono}
			if m.serial {
				lane.floors = append(lane.floors, selectionFloor{m.engine, m.step, m.sequence})
			}
			if m.action == "pop" || key.lane == "peer" && m.action == "take" {
				if !charge(len(m.input)) {
					return unavailable("selection_byte_limit")
				}
				lane.pops[m.sequence] = m
			}
		}
		slices.SortFunc(lane.floors, func(a, b selectionFloor) int {
			if a.engine < b.engine {
				return -1
			}
			if a.engine > b.engine {
				return 1
			}
			if a.step < b.step {
				return -1
			}
			if a.step > b.step {
				return 1
			}
			if a.sequence < b.sequence {
				return -1
			}
			if a.sequence > b.sequence {
				return 1
			}
			return 0
		})
		var floor uint64
		for i := range lane.floors {
			floor = max(floor, lane.floors[i].sequence)
			lane.floors[i].sequence = floor
		}
		lanes[key] = lane
	}
	names := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before validation
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		items := groups[name]
		slices.SortFunc(items, func(a, b *SelectionRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		selected := map[uint64]*SelectionRec{}
		var previous, mono uint64
		for _, r := range items {
			if r.Sequence == previous {
				return inconsistent("selection_sequence_repeated")
			}
			if r.Sequence != previous+1 {
				return unavailable("selection_sequence_gap")
			}
			if r.Mono < mono {
				return inconsistent("selection_time_changed")
			}
			previous, mono = r.Sequence, r.Mono
			if r.Action == "select" {
				report.Attempts++
				key := appCoreKey{name, r.EngineRun, r.Step}
				source := steps[key]
				var probeMono uint64
				boundary, restoredBoundary := installed[key]
				switch {
				case source != nil:
					probeMono = uint64(source.Observed.Mono)
				case restoredBoundary:
					if indexes[r] <= boundary.ready || r.Mono < boundary.installedMono {
						return inconsistent("selection_precedes_restore_installation")
					}
					probeMono = boundary.installedMono
				default:
					return unavailable("selection_preceding_core_source_missing")
				}
				expected, ok := selectedLane(r)
				if !ok || expected != r.Lane {
					return inconsistent("selection_priority_changed")
				}
				probes := []struct {
					name string
					p    InputProbe
				}{{"internal", r.Internal}, {"app", r.App}, {"timer", r.Timer}, {"peer", r.Inbox}}
				for _, item := range probes {
					p := item.p
					if p.State == "not_probed" {
						continue
					}
					lane := lanes[selectionLaneKey{name, item.name}]
					if lane == nil {
						return unavailable("selection_lane_source_missing")
					}
					if p.Sequence < lane.minimumSequence(r.EngineRun, r.Step) {
						return inconsistent("selection_probe_precedes_completed_step")
					}
					state, found := lane.states[p.Sequence]
					if !found {
						return unavailable("selection_probe_source_missing")
					}
					if p.Mono < probeMono || p.Mono > r.Mono || p.Sequence < lane.last || state.mono > p.Mono || state.ready != (p.State == "ready") {
						return inconsistent("selection_probe_changed")
					}
					if next, found := lane.states[p.Sequence+1]; p.Sequence != ^uint64(0) && found && next.mono < p.Mono {
						return inconsistent("selection_probe_source_stale")
					}
					lane.last = p.Sequence
					probeMono = p.Mono
				}
				if r.Lane == "none" {
					report.Empty++
					continue
				}
				lane := lanes[selectionLaneKey{name, r.Lane}]
				pop := lane.pops[r.Source]
				if pop == nil {
					return unavailable("selection_dequeue_source_missing")
				}
				var p InputProbe
				switch r.Lane {
				case "internal":
					p = r.Internal
				case "app":
					p = r.App
				case "timer":
					p = r.Timer
				case "peer":
					p = r.Inbox
				}
				if pop.ownerEngine > r.EngineRun || pop.ownerEngine == r.EngineRun && pop.ownerStep > r.Step {
					return inconsistent("selection_source_from_future_step")
				}
				if r.Source <= p.Sequence || lane.used[r.Source] || pop.engine != r.EngineRun || pop.step != 0 && pop.step != r.Step+1 || pop.inputKind != r.InputKind || !bytes.Equal(pop.input, r.Input) || pop.mono < p.Mono || pop.mono > r.Mono {
					return inconsistent("selection_dequeue_source_changed")
				}
				if (r.Lane == "internal" || r.Lane == "app") && r.Source != p.Sequence+1 {
					return inconsistent("selection_locked_dequeue_changed")
				}
				lane.last = r.Source
				lane.used[r.Source] = true
				selected[r.Selection] = r
				report.Selected++
				report.RandomChoices += r.Random
			} else if r.Action == "discard" {
				key, certified := bySelection[finalizeQueueKey{name, r.Selection}]
				evidence := discarded[key]
				selectedInput := selected[r.Selection]
				if !certified || consumed[key] || selectedInput == nil {
					return inconsistent("known_discard_without_original_selection")
				}
				p, c := evidence.prepare, evidence.completion
				if selectedInput.Lane != "peer" || selectedInput.EngineRun != r.EngineRun || r.EngineRun != p.EngineRun || selectedInput.Step != p.BeforeStep || r.Step != 0 || p.Selection != r.Selection || selectedInput.InputKind != r.InputKind || p.InputKind != r.InputKind || !bytes.Equal(selectedInput.Input, r.Input) || !bytes.Equal(p.Input, r.Input) || selectedInput.Mono > p.Mono || p.Mono > r.Mono || r.Mono > c.Mono {
					return inconsistent("known_discard_selection_changed")
				}
				consumed[key] = true
				delete(selected, r.Selection)
				report.DiscardedKnown++
			} else {
				selectedInput := selected[r.Selection]
				if selectedInput == nil || selectedInput.EngineRun != r.EngineRun || selectedInput.Step+1 != r.Step || selectedInput.InputKind != r.InputKind || !bytes.Equal(selectedInput.Input, r.Input) {
					return inconsistent("selection_dispatch_owner_changed")
				}
				key := appCoreKey{name, r.EngineRun, r.Step}
				source := steps[key]
				if source == nil {
					return unavailable("selection_core_dispatch_missing")
				}
				seen, required := wanted[key]
				via := selectedInput.Lane
				if !required || seen || source.Via != via || source.InputKind != r.InputKind || !bytes.Equal(source.Input, r.Input) || selectedInput.Mono > uint64(source.Entry.Mono) || r.Mono < uint64(source.Observed.Mono) {
					return inconsistent("selection_core_dispatch_changed")
				}
				wanted[key] = true
				delete(selected, r.Selection)
				report.Dispatched++
			}
		}
		report.RetainedSelected += uint64(len(selected))
	}
	for _, lane := range lanes { //wbft:unordered identical missing-source result
		for source := range lane.pops { //wbft:unordered identical missing-source result
			if !lane.used[source] {
				return unavailable("selection_for_dequeue_missing")
			}
		}
	}
	for _, seen := range wanted { //wbft:unordered identical missing-source result
		if !seen {
			return unavailable("selection_for_core_dispatch_missing")
		}
	}
	for key := range discarded { //wbft:unordered identical missing-source result
		if !consumed[key] {
			return unavailable("known_discard_without_selection_source")
		}
	}
	report.Status, report.Reason = "consistent", ""
	return report, nil
}
