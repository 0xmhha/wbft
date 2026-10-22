package journal

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type ReceiveSourceLimits struct {
	Core                       CoreSourceLimits
	Receive                    ReceiveCacheCheckLimits
	Frames, Captures, Sessions uint64
}

// ReceiveSourceCheck compares external registrations with original local raw
// reads and recomputed core ACCEPTs. It is not runner scheduling, application
// execution, network authentication/delivery or complete runtime replay proof.
type ReceiveSourceCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	ScheduleStatus string `json:"schedule_status"`
	External       uint64 `json:"external_registrations,string"`
	SelfUnverified uint64 `json:"self_inputs_unverified,string"`
}

var ErrReceiveSource = errors.New("journal: inconsistent external receive source")

type receiveSourceCoreKey struct {
	run                  string
	ledger, engine, step uint64
}
type receiveSourceOutputKey struct {
	receiveSourceCoreKey
	output uint64
}
type receiveSourceCaptureKey struct {
	run     string
	capture uint64
}
type receiveRawSource struct {
	record    *MsgRec
	peer      types.Address
	peerKnown bool
}
type receiveSessionSource struct {
	peer   types.Address
	origin bool
}

func CheckReceiveSources(records []Record, limits ReceiveSourceLimits) (ReceiveSourceCheck, error) {
	report := ReceiveSourceCheck{Status: "unavailable", Scope: "external_read_capture_core_accept", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (ReceiveSourceCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (ReceiveSourceCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrReceiveSource, reason)
	}
	if limits.Frames == 0 || limits.Captures == 0 || limits.Sessions == 0 {
		return unavailable("inspection_limits_required")
	}
	cache, err := CheckReceiveCacheTransitions(records, limits.Receive)
	if err != nil {
		return inconsistent("transition_" + cache.Reason)
	}
	if cache.Status != "consistent" {
		return unavailable("transition_" + cache.Reason)
	}
	core, accepted, err := reconstructCoreSources(records, limits.Core)
	if err != nil {
		return inconsistent("core_" + core.Reason)
	}
	if core.Status != "consistent" {
		return unavailable("core_" + core.Reason)
	}
	steps := map[receiveSourceCoreKey]*CoreStepRec{}
	outputs := map[receiveSourceOutputKey]coreSourceAccepted{}
	for _, proof := range accepted {
		if proof.receiveLedgerRun == "" || proof.receiveLedger == 0 {
			continue
		}
		key := receiveSourceOutputKey{receiveSourceCoreKey{proof.receiveLedgerRun, proof.receiveLedger, proof.engine, proof.step}, proof.output}
		if _, ok := outputs[key]; ok {
			return unavailable("ambiguous_core_source")
		}
		outputs[key] = proof
	}
	raw := map[receiveSourceCaptureKey]receiveRawSource{}
	sessions := map[SessionRef]*receiveSessionSource{}
	peers := map[string]map[uint32]types.Address{}
	wireOffsets := map[string]uint64{}
	var registrations []struct {
		run string
		t   transport.ReceiveTransition
	}
	run := ""
	var frames uint64
	missing := ""
	noteMissing := func(reason string) {
		if missing == "" {
			missing = reason
		}
	}
	for _, record := range records {
		switch b := record.Body.(type) {
		case *SegmentRec:
			run = b.Run
			if peers[run] == nil {
				peers[run] = map[uint32]types.Address{}
			}
			if old, ok := wireOffsets[run]; ok && old != b.WireOffset {
				return inconsistent("wire_offset_changed")
			}
			wireOffsets[run] = b.WireOffset
		case *PeerRec:
			if peers[run] == nil {
				return unavailable("peer_writer_missing")
			}
			if old, ok := peers[run][b.PeerIdx]; ok && old != b.Addr {
				return inconsistent("peer_index_changed")
			}
			peers[run][b.PeerIdx] = b.Addr
		case *CoreStepRec:
			if b.ReceiveLedgerRun == "" || b.ReceiveLedger == 0 {
				continue
			}
			key := receiveSourceCoreKey{b.ReceiveLedgerRun, b.ReceiveLedger, b.EngineRun, b.Step}
			if _, ok := steps[key]; ok {
				return unavailable("ambiguous_core_step_source")
			}
			steps[key] = b
		case *SessionRec:
			if b.Session == nil {
				continue
			}
			if _, err := encodeSessionRef(b.Session); err != nil || !validSessionEvent(b.Event, b.Active) {
				return inconsistent("invalid_session_source")
			}
			s := sessions[*b.Session]
			if s == nil {
				if uint64(len(sessions)) >= limits.Sessions {
					return unavailable("session_limit")
				}
				s = &receiveSessionSource{peer: b.Peer}
				sessions[*b.Session] = s
			} else if s.peer != b.Peer {
				return inconsistent("session_peer_changed")
			}
			if run == b.Session.Run && b.Event == SessionObserved {
				s.origin = true
			}
		case *MsgRec:
			if b.Dir != In {
				continue
			}
			frames++
			if frames > limits.Frames {
				return unavailable("frame_limit")
			}
			if b.Capture == 0 {
				continue
			}
			if run == "" {
				return unavailable("raw_writer_missing")
			}
			key := receiveSourceCaptureKey{run, b.Capture}
			if _, ok := raw[key]; ok {
				return inconsistent("capture_reused")
			}
			if uint64(len(raw)) >= limits.Captures {
				return unavailable("capture_limit")
			}
			peer, known := peers[run][b.PeerIdx]
			raw[key] = receiveRawSource{record: b, peer: peer, peerKnown: known}
		case *ReceiveCacheRec:
			t := b.Transition
			if t.Action == transport.ReceiveCheckAccept && (t.Decision == transport.ReceiveRegistered || t.Decision == transport.ReceiveDuplicate) {
				registrations = append(registrations, struct {
					run string
					t   transport.ReceiveTransition
				}{run, t})
			}
		case *GapRec:
			if b.Dropped > 0 && len(b.ByKind) == 0 {
				noteMissing("unclassified_gap")
			}
			for _, kind := range b.ByKind {
				if kind.Count > 0 && (kind.Kind == 0 || kind.Kind == uint64(KindMsg) || kind.Kind == uint64(KindPeer) || kind.Kind == uint64(KindSession) || kind.Kind == uint64(KindCoreStep) || kind.Kind == uint64(KindReceiveCache)) {
					noteMissing("receive_source_gap")
				}
			}
		}
	}
	for _, registration := range registrations {
		t := registration.t
		key := receiveSourceCoreKey{registration.run, t.Ledger, t.Source.EngineRun, t.Source.Step}
		step := steps[key]
		if step == nil {
			noteMissing("original_core_step_missing")
			continue
		}
		if step.ReceiveScopeBefore != t.Scope {
			return inconsistent("original_scope_changed")
		}
		proof, ok := outputs[receiveSourceOutputKey{key, t.Source.Output}]
		if !ok {
			return inconsistent("registration_without_core_accept")
		}
		if !proof.input.present || proof.via != t.Source.Via || proof.peer != t.Checked.Peer || proof.code != t.Checked.Code || proof.key != t.Checked.Key {
			return inconsistent("core_accept_input_changed")
		}
		if !t.ContextKnown || !proof.beforeKnown {
			noteMissing("checking_context_missing")
			continue
		}
		if t.Context != proof.before {
			return inconsistent("checking_context_changed")
		}
		if t.Source.Via == "self" {
			report.SelfUnverified++
			continue
		}
		if t.Origin.WriterRun == "" || t.Origin.CaptureID == 0 {
			noteMissing("original_capture_unqualified")
			continue
		}
		if t.Origin != t.CheckedOrigin || t.Origin != proof.origin {
			return inconsistent("capture_origin_changed")
		}
		if t.Input.SessionRun == "" || t.Input.Session == 0 {
			noteMissing("original_stream_unqualified")
			continue
		}
		if t.Input != t.Checked || t.Checked != proof.input.identity {
			return inconsistent("original_checked_input_changed")
		}
		frame, ok := raw[receiveSourceCaptureKey{t.Origin.WriterRun, t.Origin.CaptureID}]
		if !ok {
			noteMissing("original_raw_capture_missing")
			continue
		}
		if !frame.peerKnown {
			noteMissing("raw_peer_missing")
			continue
		}
		if frame.peer != t.Input.Peer {
			return inconsistent("raw_peer_changed")
		}
		b := frame.record
		if b.Session == nil {
			noteMissing("raw_session_missing")
			continue
		}
		ref := SessionRef{Run: t.Input.SessionRun, Ordinal: t.Input.Session}
		if *b.Session != ref {
			return inconsistent("raw_session_changed")
		}
		session := sessions[ref]
		if session == nil || !session.origin {
			noteMissing("session_origin_missing")
			continue
		}
		if session.peer != t.Input.Peer {
			return inconsistent("session_peer_changed")
		}
		if b.Offer != transport.OfferQueued {
			return inconsistent("unoffered_capture_registered")
		}
		if b.Size > uint64(len(b.Payload)) {
			noteMissing("raw_payload_missing")
			continue
		}
		offset := wireOffsets[t.Origin.WriterRun]
		if b.Code > ^uint64(0)-offset || b.WireCode != b.Code+offset {
			return inconsistent("raw_wire_code_changed")
		}
		payload, code, action, _ := transport.DecodeFrame(b.Code, b.Payload)
		if action != transport.FrameDeliver || code != t.Input.Code || codec.DedupKey(payload) != t.Input.Key || types.Hash(sha256.Sum256(payload)) != t.Input.PayloadSHA256 {
			return inconsistent("raw_frame_input_changed")
		}
		report.External++
	}
	if missing != "" {
		return unavailable(missing)
	}
	if report.External == 0 {
		return unavailable("no_external_receive_registrations")
	}
	report.Status = "consistent"
	return report, nil
}
