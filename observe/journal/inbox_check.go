package journal

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// InboxLimits bound inspection indexes and encoded spans, not runtime admission,
// decoding allocations, process heap or the operating inbox resource budget.
type InboxLimits struct {
	Core                                      CoreSourceLimits
	Operations, Entries, Peers, Frames, Bytes uint64
}

type InboxCheck struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Scope            string `json:"scope"`
	PhysicalStatus   string `json:"physical_status"`
	ScheduleStatus   string `json:"schedule_status"`
	Appended         uint64 `json:"appended,string"`
	Dequeued         uint64 `json:"dequeued,string"`
	Checked          uint64 `json:"checked,string"`
	CachedFailures   uint64 `json:"cached_failures,string,omitempty"`
	Taken            uint64 `json:"taken,string"`
	Dispatched       uint64 `json:"dispatched,string"`
	DiscardedKnown   uint64 `json:"discarded_known,string"`
	Clears           uint64 `json:"clears,string"`
	RetainedQueued   uint64 `json:"retained_queued,string"`
	RetainedChecking uint64 `json:"retained_checking,string"`
	RetainedSlots    uint64 `json:"retained_slots,string"`
	RetainedTaken    uint64 `json:"retained_taken,string"`
}

var ErrInboxSource = errors.New("journal: inconsistent inbox source")

type inboxSlotKey struct {
	signer     types.Address
	seq, round string
	code       uint64
	second     bool
}
type inboxSourceSnapshot struct {
	source   *CoreStepRec
	snapshot *consensus.Snapshot
}
type inboxModel struct {
	order      []types.Address
	queues     map[types.Address][]*InboxRec
	ready      map[types.Address][]inboxSlotKey
	slots      map[inboxSlotKey]*InboxRec
	pending    map[uint64]*InboxRec
	checking   map[uint64]bool
	taken      map[uint64]*InboxRec
	wIdx, cIdx uint64
}

func sameInboxIdentity(a, b *InboxRec) bool {
	return a.Peer == b.Peer && a.Code == b.Code && a.Capture == b.Capture && a.RecvMono == b.RecvMono && a.Origin == b.Origin && a.StreamRun == b.StreamRun && a.Stream == b.Stream
}

func inboxWindow(snapshot *consensus.Snapshot, code codec.Code, view types.View) bool {
	if snapshot == nil || !snapshot.Running {
		return false
	}
	if distance, ok := snapshot.View.Sequence.Sub(view.Sequence); ok && distance.CmpUint64(1) > 0 {
		return true
	}
	if consensus.CheckMessage(snapshot.View, snapshot.State, snapshot.PriorRound, code, view) != consensus.TooFar {
		return false
	}
	if view.Sequence.Cmp(snapshot.View.Sequence) <= 0 {
		return true
	}
	next := types.View{Sequence: snapshot.View.Sequence.AddUint64(1)}
	return consensus.CheckMessage(next, consensus.AcceptRequest, types.Round{}, code, view) == consensus.TooFar
}

// CheckInboxSources reconstructs peer queues, original worker selection and
// slots from independently recovered original frames and independently executed
// published core snapshots. It checks finite observed boundaries. Internal/app/
// timer priority and random scheduling outside this inbox remain unavailable.
func CheckInboxSources(records []Record, limits InboxLimits) (InboxCheck, error) {
	return checkInboxSources(records, limits, nil)
}

func checkInboxSources(records []Record, limits InboxLimits, discarded receiveDiscardEvidenceSet) (InboxCheck, error) {
	return inspectInboxSources(records, limits, discarded, false)
}

// CheckRestoredInboxSources binds replay snapshot references to independently
// reconstructed WAL installations. The ordinary guard and private Known-discard
// requirements remain unchanged, and no synthetic live core step is created.
func CheckRestoredInboxSources(records []Record, limits InboxLimits) (InboxCheck, error) {
	_, core, effects, err := CheckRestoredBoundarySources(records, limits.Core)
	report := InboxCheck{Status: "unavailable", Reason: "restore_boundary_not_reconstructed", Scope: "inbox_on_original_wal_restore_and_live_core", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	if err != nil || core.Status != "consistent" || effects.Status != "consistent" {
		if err != nil {
			report.Status = "inconsistent"
		}
		return report, err
	}
	report, err = inspectInboxSources(records, limits, nil, true)
	report.Scope = "inbox_on_original_wal_restore_and_live_core"
	return report, err
}

type restoredInboxSnapshot struct {
	snapshot  *consensus.Snapshot
	readIndex int
	readMono  uint64
}

func inspectInboxSources(records []Record, limits InboxLimits, discarded receiveDiscardEvidenceSet, restored bool) (InboxCheck, error) {
	return inspectInboxSourcesProfile(records, limits, discarded, restored, nil)
}

// Only the private failure checker supplies this evidence after independently
// reconstructing original failure checks and the bounded cache history.
type failureInboxEvidenceSet map[*InboxRec]bool

func inspectInboxSourcesProfile(records []Record, limits InboxLimits, discarded receiveDiscardEvidenceSet, restored bool, failures failureInboxEvidenceSet) (InboxCheck, error) {
	consumed := map[receiveDiscardKey]bool{}
	report := InboxCheck{Status: "unavailable", Scope: "inbox_queue_worker_snapshot_slot_and_core_input_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (InboxCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (InboxCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrInboxSource, reason)
	}
	if limits.Operations == 0 || limits.Entries == 0 || limits.Peers == 0 || limits.Frames == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	replayed := map[appCoreKey]restoredInboxSnapshot{}
	if restored {
		restore, seeds, e := reconstructRestoreSources(records, limits.Core)
		if e != nil {
			return inconsistent("restore_" + restore.Reason)
		}
		if restore.Status != "consistent" {
			return unavailable("restore_" + restore.Reason)
		}
		for key, seed := range seeds { //wbft:unordered independent snapshot indexes commute
			replayed[appCoreKey{key.writer, key.engine, seed.installed.Steps}] = restoredInboxSnapshot{seed.model.state.Snapshot(), seed.readIndex, seed.read.Mono}
		}
	}
	indexes := map[*InboxRec]int{}
	snapshots := map[appCoreKey]inboxSourceSnapshot{}
	wanted, stops := map[appCoreKey]bool{}, map[appCoreKey]bool{}
	captureSnapshot := func(writer string, source *CoreStepRec, snapshot *consensus.Snapshot) {
		key := appCoreKey{writer, source.EngineRun, source.Step}
		snapshots[key] = inboxSourceSnapshot{source, snapshot}
		if source.Via == "peer" && source.InputKind == inputlog.KindMessage {
			wanted[key] = false
		}
		if source.InputKind == inputlog.KindStop {
			stops[key] = false
		}
	}
	var core CoreSourceCheck
	var err error
	if failures != nil {
		if restored {
			return unavailable("receive_failure_restore_profile_unavailable")
		}
		core, _, err = inspectCoreSourceProfile(records, limits.Core, nil, captureSnapshot, nil, true)
	} else {
		core, _, err = inspectConditionalCoreStates(records, limits.Core, restored, nil, captureSnapshot)
	}
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	groups := map[string][]*InboxRec{}
	raw := map[receiveSourceCaptureKey]receiveRawSource{}
	peers := map[string]map[uint32]types.Address{}
	offsets := map[string]uint64{}
	sessions := map[SessionRef]types.Address{}
	writer := ""
	var span, operations, frames uint64
	for index, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
			if old, exists := offsets[writer]; exists && old != r.WireOffset {
				return inconsistent("wire_offset_changed")
			}
			offsets[writer] = r.WireOffset
			if peers[writer] == nil {
				peers[writer] = map[uint32]types.Address{}
			}
		case *PeerRec:
			if writer == "" {
				return unavailable("peer_writer_missing")
			}
			if _, exists := peers[writer][r.PeerIdx]; !exists && uint64(len(peers[writer])) >= limits.Peers {
				return unavailable("peer_index_limit")
			}
			if old, exists := peers[writer][r.PeerIdx]; exists && old != r.Addr {
				return inconsistent("peer_identity_changed")
			}
			peers[writer][r.PeerIdx] = r.Addr
		case *SessionRec:
			if r.Session != nil && r.Event == SessionObserved {
				if _, exists := sessions[*r.Session]; !exists && uint64(len(sessions)) >= limits.Frames {
					return unavailable("stream_index_limit")
				}
				if old, exists := sessions[*r.Session]; exists && old != r.Peer {
					return inconsistent("session_peer_changed")
				}
				sessions[*r.Session] = r.Peer
			}
		case *MsgRec:
			if r.Dir != In || r.Capture == 0 {
				continue
			}
			if frames >= limits.Frames {
				return unavailable("frame_limit")
			}
			n := uint64(size(Record{Body: r}))
			if n > limits.Bytes-span {
				return unavailable("byte_limit")
			}
			span += n
			frames++
			key := receiveSourceCaptureKey{writer, r.Capture}
			if _, exists := raw[key]; exists {
				return inconsistent("capture_repeated")
			}
			peer, known := peers[writer][r.PeerIdx]
			raw[key] = receiveRawSource{r, peer, known}
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && k.Kind == uint64(KindInboxFailureHit) {
					return unavailable("inbox_failure_source_gap")
				}
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindInbox) || k.Kind == uint64(KindMsg) || k.Kind == uint64(KindPeer)) {
					return unavailable("inbox_source_gap")
				}
			}
		case *InboxRec:
			if operations >= limits.Operations {
				return unavailable("operation_limit")
			}
			operations++
			if r.Version != InboxSourceVersion {
				return unavailable("inbox_version")
			}
			if !validInboxRec(r) {
				return inconsistent("invalid_inbox_source")
			}
			if r.Unavailable != "" {
				_, certified := discarded[receiveDiscardKey{writer, r.EngineRun, r.Request}]
				if r.Action != "discard" || r.Unavailable != "dispatch_deduplicated" || !certified {
					return unavailable("inbox_" + r.Unavailable)
				}
			}
			if writer == "" {
				return unavailable("inbox_writer_missing")
			}
			n := uint64(size(Record{Body: r}))
			if n > limits.Bytes-span {
				return unavailable("byte_limit")
			}
			span += n
			groups[writer] = append(groups[writer], r)
			indexes[r] = index
		case *InboxFailureHitRec:
			if failures == nil || !failures[&r.Source] {
				return unavailable("receive_failure_source_profile_unavailable")
			}
			if operations >= limits.Operations {
				return unavailable("operation_limit")
			}
			operations++
			if !validInboxFailureHit(r) {
				return inconsistent("invalid_inbox_failure_hit")
			}
			if r.Unavailable != "" || r.Source.Unavailable != "" || writer == "" {
				return unavailable("inbox_failure_source_missing")
			}
			n := uint64(size(record))
			if n > limits.Bytes-span {
				return unavailable("byte_limit")
			}
			span += n
			groups[writer] = append(groups[writer], &r.Source)
			indexes[&r.Source] = index
		}
	}
	if operations == 0 {
		return unavailable("no_inbox_sources")
	}
	writers := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before inspection
		writers = append(writers, name)
	}
	slices.Sort(writers)
	// One original queued frame proves at most one admission. This index is
	// bounded by the already checked original raw capture count.
	admittedCaptures := map[receiveSourceCaptureKey]bool{}
	for _, name := range writers {
		items := groups[name]
		slices.SortFunc(items, func(a, b *InboxRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		model := inboxModel{queues: map[types.Address][]*InboxRec{}, ready: map[types.Address][]inboxSlotKey{}, slots: map[inboxSlotKey]*InboxRec{}, pending: map[uint64]*InboxRec{}, checking: map[uint64]bool{}, taken: map[uint64]*InboxRec{}}
		var sequence, mono uint64
		for _, r := range items {
			if r.Sequence == sequence {
				return inconsistent("sequence_repeated")
			}
			if r.Sequence != sequence+1 {
				return unavailable("sequence_gap")
			}
			if r.Mono < mono {
				return inconsistent("clock_reversed")
			}
			sequence, mono = r.Sequence, r.Mono
			if uint64(len(r.Order)) > limits.Peers {
				return unavailable("peer_limit")
			}
			if len(r.Order) < len(model.order) || !slices.Equal(r.Order[:len(model.order)], model.order) {
				return inconsistent("peer_order_changed")
			}
			seen := map[types.Address]bool{}
			for _, peer := range r.Order {
				if seen[peer] {
					return inconsistent("peer_order_repeated")
				}
				seen[peer] = true
			}
			model.order = slices.Clone(r.Order)
			original := model.pending[r.Request]
			if r.Action != "append" && r.Action != "clear" && (original == nil || !sameInboxIdentity(original, r)) {
				return inconsistent("request_identity_changed")
			}
			queue := model.queues[r.Peer]
			var bytesBefore uint64
			for _, item := range queue {
				bytesBefore += uint64(len(item.Payload))
			}
			switch r.Action {
			case "append":
				if !seen[r.Peer] {
					return inconsistent("append_peer_missing")
				}
				if uint64(len(model.pending)) >= limits.Entries {
					return unavailable("entry_limit")
				}
				if r.Origin.WriterRun == "" || r.Capture == 0 || r.Origin.CaptureID != r.Capture || r.StreamRun == "" || r.Stream == 0 {
					return unavailable("original_frame_source_missing")
				}
				captureKey := receiveSourceCaptureKey{r.Origin.WriterRun, r.Capture}
				if admittedCaptures[captureKey] {
					return inconsistent("capture_appended_twice")
				}
				frame, exists := raw[captureKey]
				if !exists || !frame.peerKnown {
					return unavailable("original_frame_missing")
				}
				f := frame.record
				payload, code, action, _ := transport.DecodeFrame(f.Code, f.Payload)
				if action != transport.FrameDeliver || code != r.Code || f.Code > ^uint64(0)-offsets[r.Origin.WriterRun] || f.WireCode != f.Code+offsets[r.Origin.WriterRun] {
					return inconsistent("original_wire_frame_changed")
				}
				if peer, exists := sessions[SessionRef{Run: r.StreamRun, Ordinal: r.Stream}]; !exists {
					return unavailable("original_stream_missing")
				} else if peer != r.Peer {
					return inconsistent("original_stream_peer_changed")
				}
				if f.Session == nil || f.Size > uint64(len(f.Payload)) {
					return unavailable("original_frame_metadata_missing")
				}
				if frame.peer != r.Peer || !bytes.Equal(payload, r.Payload) || f.Offer != transport.OfferQueued || f.Session.Run != r.StreamRun || f.Session.Ordinal != r.Stream {
					return inconsistent("original_frame_changed")
				}
				if r.Before != uint64(len(queue)) || r.BytesBefore != bytesBefore || r.BytesAfter != bytesBefore+uint64(len(r.Payload)) {
					return inconsistent("append_queue_changed")
				}
				admittedCaptures[captureKey] = true
				model.pending[r.Request] = r
				model.queues[r.Peer] = append(queue, r)
				report.Appended++
			case "dequeue":
				candidates := []types.Address{}
				for _, peer := range model.order {
					if len(model.queues[peer]) > 0 {
						candidates = append(candidates, peer)
					}
				}
				if !slices.Equal(candidates, r.Candidates) || len(candidates) == 0 {
					return inconsistent("worker_candidates_changed")
				}
				choice := r.Choice
				if r.Manual == 0 {
					model.wIdx = (model.wIdx + 1) % uint64(len(candidates))
					choice = model.wIdx
				}
				if choice >= uint64(len(candidates)) || candidates[choice] != r.Peer || len(queue) == 0 || queue[0].Request != r.Request || r.Before != uint64(len(queue)) || r.BytesBefore != bytesBefore || r.BytesAfter != bytesBefore-uint64(len(original.Payload)) {
					return inconsistent("worker_fifo_or_choice_changed")
				}
				model.queues[r.Peer] = queue[1:]
				model.checking[r.Request] = true
				report.Dequeued++
			case "check", "failure_hit":
				if !model.checking[r.Request] {
					return inconsistent("check_without_dequeue")
				}
				publication, exists := snapshots[appCoreKey{name, r.SnapshotEngine, r.SnapshotStep}]
				phase := "step"
				var earliest int64
				if (r.SnapshotReplayed != 0 || r.SnapshotPhase == "replay") && !restored {
					return unavailable("restored_prefix_not_reconstructed")
				}
				if r.SnapshotPhase == "replay" {
					boundary, ok := replayed[appCoreKey{name, r.SnapshotEngine, r.SnapshotStep}]
					if !ok {
						return unavailable("restored_snapshot_publication_missing")
					}
					if r.SnapshotReplayed != 1 || r.SnapshotPhase != "replay" || indexes[r] <= boundary.readIndex {
						return inconsistent("restored_snapshot_owner_or_order_changed")
					}
					publication = inboxSourceSnapshot{snapshot: boundary.snapshot}
					exists, phase, earliest = true, "replay", int64(boundary.readMono)
				} else if r.SnapshotPhase == "initial" && r.SnapshotEngine == 0 && r.SnapshotStep == 0 {
					publication = inboxSourceSnapshot{snapshot: &consensus.Snapshot{}}
					if r.SnapshotReplayed != 0 {
						return inconsistent("snapshot_replayed_owner_changed")
					}
					exists, phase = true, "initial"
				} else if exists {
					// A restored engine retains its prefix label on later actual
					// live publications. The label does not turn those snapshots
					// into the initial replay installation or erase their owner.
					if r.SnapshotReplayed != boolUint(publication.source.ReplayedPrefix) {
						return inconsistent("snapshot_replayed_owner_changed")
					}
					earliest = publication.source.Entry.Mono
					if publication.source.InputKind == inputlog.KindStart {
						phase = "start"
					}
					if publication.source.InputKind == inputlog.KindStop {
						phase = "stopped"
					}
				}
				if !exists {
					return unavailable("snapshot_publication_missing")
				}
				if earliest > int64(r.Mono) {
					return inconsistent("snapshot_from_future_step")
				}
				if r.SnapshotPhase != phase {
					return inconsistent("snapshot_phase_changed")
				}
				digest, e := InboxSnapshotDigest(publication.snapshot)
				if e != nil {
					return unavailable("snapshot_encoding")
				}
				if digest != r.SnapshotContextHash {
					return inconsistent("snapshot_context_changed")
				}
				if r.Action == "failure_hit" {
					if !failures[r] {
						return inconsistent("uncertified_failure_hit")
					}
					delete(model.pending, r.Request)
					delete(model.checking, r.Request)
					report.CachedFailures++
					break
				}
				member := func(a types.Address, _ types.View) bool {
					s := publication.snapshot
					return !s.Running || s.Validators != nil && s.Validators.Contains(a) || s.PriorValidators != nil && s.PriorValidators.Contains(a)
				}
				v, recoverError := consensus.Recover(codec.Code(original.Code), original.Payload, member)
				result := ""
				if recoverError != nil {
					result = "signature"
					if errors.Is(recoverError, ecdsa.ErrUnauthorizedAddress) {
						result = "membership"
					}
				} else if inboxWindow(publication.snapshot, codec.Code(original.Code), v.Msg.View) {
					result = "window"
				}
				if result != "" {
					if r.Result != result {
						return inconsistent("check_result_changed")
					}
					delete(model.pending, r.Request)
				} else {
					key := inboxSlotKey{v.Source, v.Msg.View.Sequence.String(), v.Msg.View.Round.String(), original.Code, false}
					first := model.slots[key]
					if original.Code == uint64(codec.CodePreprepare) && v.Msg.View.Round.IsZero() && first != nil && codec.DedupKey(model.pending[first.Request].Payload) != codec.DedupKey(original.Payload) {
						key.second = true
					}
					slot := model.slots[key]
					holder, old := original.Peer, uint64(0)
					result = "insert"
					if slot != nil {
						holder, old, result = slot.Holder, slot.Request, "replace"
						if codec.DedupKey(model.pending[slot.Request].Payload) == codec.DedupKey(original.Payload) {
							result = "duplicate"
						}
					} else if key.second && first != nil {
						holder = first.Holder
					}
					if r.Signer != key.signer || r.ViewSequence != key.seq || r.ViewRound != key.round || (r.Second == 1) != key.second || r.Holder != holder || r.OldRequest != old || r.Result != result {
						return inconsistent("slot_decision_changed")
					}
					if result == "duplicate" {
						delete(model.pending, r.Request)
					} else {
						if slot == nil {
							model.ready[holder] = append(model.ready[holder], key)
						} else {
							delete(model.pending, slot.Request)
						}
						model.slots[key] = r
					}
				}
				delete(model.checking, r.Request)
				report.Checked++
			case "take":
				var key inboxSlotKey
				var selected *InboxRec
				for range len(model.order) {
					model.cIdx = (model.cIdx + 1) % uint64(len(model.order))
					peer := model.order[model.cIdx]
					for len(model.ready[peer]) > 0 {
						key = model.ready[peer][0]
						model.ready[peer] = model.ready[peer][1:]
						if selected = model.slots[key]; selected != nil {
							break
						}
					}
					if selected != nil {
						break
					}
				}
				if selected == nil || selected.Request != r.Request || selected.Holder != r.Holder || key.signer != r.Signer || key.seq != r.ViewSequence || key.round != r.ViewRound || key.second != (r.Second == 1) {
					return inconsistent("consensus_slot_selection_changed")
				}
				model.taken[r.Request] = r
				delete(model.slots, key)
				report.Taken++
			case "discard":
				key := receiveDiscardKey{name, r.EngineRun, r.Request}
				evidence, certified := discarded[key]
				selected := model.taken[r.Request]
				if !certified || consumed[key] || selected == nil || selected.EngineRun != r.EngineRun {
					return inconsistent("known_discard_without_original_take")
				}
				p, c := evidence.prepare, evidence.completion
				in, e := inputlog.Decode(p.InputKind, p.Input, nil)
				m, ok := in.(consensus.Message)
				if e != nil || !ok || uint64(m.Code) != original.Code || m.Peer != original.Peer || uint64(m.RecvMono) != original.RecvMono || !bytes.Equal(m.Payload, original.Payload) || p.Origin != original.Origin || p.StreamRun != original.StreamRun || p.Stream != original.Stream || p.Capture != original.Capture || p.InboxRequest != r.Request || p.EngineRun != r.EngineRun || selected.Mono > p.Mono || p.Mono > r.Mono || r.Mono > c.Mono || r.Step != 0 {
					return inconsistent("known_discard_original_input_changed")
				}
				consumed[key] = true
				delete(model.taken, r.Request)
				delete(model.pending, r.Request)
				report.DiscardedKnown++
			case "dispatch":
				selected := model.taken[r.Request]
				if selected == nil || selected.EngineRun != r.EngineRun {
					return inconsistent("dispatch_without_original_take")
				}
				coreKey := appCoreKey{name, r.EngineRun, r.Step}
				source, exists := snapshots[coreKey]
				if !exists {
					return unavailable("taken_core_input_missing")
				}
				if matched, exists := wanted[coreKey]; !exists || matched {
					return inconsistent("taken_core_input_repeated_or_foreign")
				}
				in, e := inputlog.Decode(source.source.InputKind, source.source.Input, nil)
				message, ok := in.(consensus.Message)
				if e != nil || !ok || uint64(message.Code) != original.Code || message.Peer != original.Peer || uint64(message.RecvMono) != original.RecvMono || !bytes.Equal(message.Payload, original.Payload) || source.source.Origin != original.Origin || source.source.StreamRun != original.StreamRun || source.source.Stream != original.Stream {
					return inconsistent("taken_core_input_changed")
				}
				wanted[coreKey] = true
				delete(model.taken, r.Request)
				delete(model.pending, r.Request)
				report.Dispatched++
			case "clear":
				coreKey := appCoreKey{name, r.EngineRun, r.Step}
				matched, exists := stops[coreKey]
				if !exists {
					return unavailable("stop_source_missing")
				}
				if matched {
					return inconsistent("stop_clear_repeated")
				}
				stops[coreKey] = true
				var count, payloadBytes uint64
				for _, peer := range model.order {
					for _, item := range model.queues[peer] {
						count++
						payloadBytes += uint64(len(item.Payload))
						delete(model.pending, item.Request)
					}
				}
				if r.Before != count || r.BytesBefore != payloadBytes {
					return inconsistent("clear_queue_changed")
				}
				for _, slot := range model.slots { //wbft:unordered every retained slot is cleared
					delete(model.pending, slot.Request)
				}
				model.queues = map[types.Address][]*InboxRec{}
				model.ready = map[types.Address][]inboxSlotKey{}
				model.slots = map[inboxSlotKey]*InboxRec{}
				report.Clears++
			}
			if r.WorkerCursor != model.wIdx || r.ConsensusCursor != model.cIdx {
				return inconsistent("cursor_changed")
			}
		}
		for _, queue := range model.queues { //wbft:unordered a sum
			report.RetainedQueued += uint64(len(queue))
		}
		report.RetainedChecking += uint64(len(model.checking))
		report.RetainedSlots += uint64(len(model.slots))
		report.RetainedTaken += uint64(len(model.taken))
	}
	for _, found := range wanted { //wbft:unordered all missing inputs have the same result
		if !found {
			return unavailable("core_peer_input_without_inbox_source")
		}
	}
	for _, found := range stops { //wbft:unordered all missing clears have the same result
		if !found {
			return unavailable("stop_without_inbox_clear")
		}
	}
	for key := range discarded { //wbft:unordered identical missing-source result
		if !consumed[key] {
			return unavailable("known_discard_without_inbox_source")
		}
	}
	report.Status = "consistent"
	return report, nil
}
