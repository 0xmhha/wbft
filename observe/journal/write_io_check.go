package journal

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// WriteIOCheckLimits bound offline metadata indexes, not WAL reading, payload
// allocations or node heap. Every limit is required explicitly.
type WriteIOCheckLimits struct {
	Records, Ledgers, Reordered, Sessions, Requests, Frames uint64
}

// WriteIOCheck compares original reservations with retained local I/O sources.
// Status describes this comparison only. PhysicalStatus stays unavailable:
// accepted-input/core/authority reconstruction and runtime replay are separate.
// Neither a successful local write nor this report proves remote delivery.
type WriteIOCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	PhysicalStatus string `json:"physical_status"`
	Reservations   uint64 `json:"reservations,string"`
	Writes         uint64 `json:"writes,string"`
	Unmeasured     uint64 `json:"unmeasured,string"`
	AcceptedInputs uint64 `json:"accepted_inputs_unverified,string"`
}

var ErrWriteIOSource = errors.New("journal: inconsistent write I/O source")

type writeIORequestKey struct {
	run             string
	ledger, request uint64
}
type writeIOSession struct {
	peer          types.Address
	origin, ended bool
}
type writeIORequest struct {
	prepared bool
	input    transport.WriteIdentity
	queue    *transport.SendResult
	complete *transport.WriteTransition
	retired  bool
	frame    *MsgRec
}

// CheckWriteIOSources does not feed observations back into an executing cache.
// It first checks the independent transition model, then indexes exact source
// references. Callback arrival may precede queue acknowledgement or follow a
// normal close; no wall/monotonic order is invented across recording writers.
func CheckWriteIOSources(records []Record, limits WriteIOCheckLimits) (WriteIOCheck, error) {
	report := WriteIOCheck{Status: "unavailable", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (WriteIOCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	inconsistent := func(reason string) (WriteIOCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrWriteIOSource, reason)
	}
	if limits.Records == 0 || limits.Ledgers == 0 || limits.Reordered == 0 || limits.Sessions == 0 || limits.Requests == 0 || limits.Frames == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	model, err := CheckWriteCacheTransitions(records, WriteCacheCheckLimits{Records: limits.Records, Ledgers: limits.Ledgers, Reordered: limits.Reordered})
	if err != nil {
		return inconsistent("transition_" + model.Reason)
	}
	if model.Status != "consistent" {
		return unavailable("transition_" + model.Reason)
	}
	requests := map[writeIORequestKey]*writeIORequest{}
	sessions := map[SessionRef]*writeIOSession{}
	peers := map[string]map[uint32]types.Address{}
	nodes := map[string]types.Address{}
	run := ""
	missing := ""
	noteMissing := func(reason string) {
		if missing == "" {
			missing = reason
		}
	}
	// Requests and frames are separately capped: a stream of orphan raw sources
	// must not grow the request map or evade the physical-source frame budget.
	frames := uint64(0)
	attempts := map[struct {
		run      string
		sequence uint64
	}]writeIORequestKey{}
	request := func(key writeIORequestKey) *writeIORequest {
		if r := requests[key]; r != nil {
			return r
		}
		if uint64(len(requests)) >= limits.Requests {
			return nil
		}
		r := new(writeIORequest)
		requests[key] = r
		return r
	}
	for _, record := range records {
		switch b := record.Body.(type) {
		case *SegmentRec:
			run = b.Run
			if old, ok := nodes[run]; ok && old != b.Self {
				return inconsistent("writer_node_changed")
			}
			nodes[run] = b.Self
			if peers[run] == nil {
				peers[run] = map[uint32]types.Address{}
			}
		case *PeerRec:
			if peers[run] == nil {
				return unavailable("peer_writer_missing")
			}
			if old, ok := peers[run][b.PeerIdx]; ok && old != b.Addr {
				return inconsistent("peer_index_changed")
			}
			peers[run][b.PeerIdx] = b.Addr
		case *GapRec:
			if b.Dropped > 0 && len(b.ByKind) == 0 {
				noteMissing("unclassified_gap")
			}
			for _, k := range b.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindMsg) || k.Kind == uint64(KindSession) || k.Kind == uint64(KindPeer) || k.Kind == uint64(KindWriteCache)) {
					noteMissing("write_source_gap")
				}
			}
		case *SessionRec:
			if run == "" {
				return unavailable("session_writer_missing")
			}
			if !validSessionEvent(b.Event, b.Active) {
				return inconsistent("invalid_session_event")
			}
			if b.Session == nil {
				noteMissing("session_reference_missing")
				continue
			}
			if _, err := encodeSessionRef(b.Session); err != nil {
				return inconsistent("invalid_session_reference")
			}
			e := sessions[*b.Session]
			if e == nil {
				if uint64(len(sessions)) >= limits.Sessions {
					return unavailable("session_limit")
				}
				e = &writeIOSession{peer: b.Peer}
				sessions[*b.Session] = e
			} else if e.peer != b.Peer {
				return inconsistent("session_peer_changed")
			}
			if b.Event == SessionObserved && run == b.Session.Run {
				e.origin = true
			}
			if b.Event != SessionObserved {
				e.ended = true
			}
		case *WriteCacheRec:
			t := b.Transition
			if t.Action == transport.WriteAccept && t.Registered {
				report.AcceptedInputs++
			}
			if t.Action == transport.WriteClose {
				for key, r := range requests { //wbft:unordered retiring independent requests commutes
					if key.run == run && key.ledger == t.Ledger {
						r.retired = true
					}
				}
				continue
			}
			if t.Action == transport.WritePrune || t.Action == transport.WritePrepare {
				for _, id := range t.Pruned {
					r := request(writeIORequestKey{run, t.Ledger, id})
					if r == nil {
						return unavailable("request_limit")
					}
					r.retired = true
				}
			}
			if t.Request == 0 {
				continue
			}
			r := request(writeIORequestKey{run, t.Ledger, t.Request})
			if r == nil {
				return unavailable("request_limit")
			}
			switch t.Action {
			case transport.WritePrepare:
				if r.prepared {
					return inconsistent("reservation_repeated")
				}
				r.prepared, r.input = true, t.Input
				report.Reservations++
			case transport.WriteQueueResult:
				if r.queue != nil {
					return inconsistent("queue_result_repeated")
				}
				q := t.Queue
				r.queue = &q
			case transport.WriteComplete:
				if t.Owned && t.Matched && t.Valid {
					if r.complete != nil {
						return inconsistent("terminal_receipt_repeated")
					}
					copy := t
					r.complete = &copy
				}
			}
		case *MsgRec:
			if b.WriteAttempt == nil {
				continue
			}
			frames++
			if frames > limits.Frames {
				return unavailable("frame_limit")
			}
			if b.Dir != Out || b.Attempt != nil {
				return inconsistent("mixed_write_source_domain")
			}
			if _, err := encodeWriteAttempt(b.WriteAttempt); err != nil {
				return inconsistent("invalid_write_source")
			}
			a := b.WriteAttempt
			if run == "" || a.WriterRun != run {
				return inconsistent("write_source_owner_changed")
			}
			key := writeIORequestKey{a.WriterRun, a.Ledger, a.Request}
			attemptKey := struct {
				run      string
				sequence uint64
			}{run, a.Sequence}
			if old, ok := attempts[attemptKey]; ok && old != key {
				return inconsistent("write_attempt_sequence_reused")
			}
			attempts[attemptKey] = key
			r := request(key)
			if r == nil {
				return unavailable("request_limit")
			}
			if r.frame != nil {
				return inconsistent("reservation_written_twice")
			}
			r.frame = b
			if b.IO == nil {
				report.Unmeasured++
			} else if _, err := encodeIO(b.IO, b.Mono); err != nil {
				return inconsistent("invalid_io_interval")
			}
		}
	}
	keys := make([]writeIORequestKey, 0, len(requests))
	for key := range requests { //wbft:unordered request references are sorted before diagnostics
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b writeIORequestKey) int {
		if c := cmp.Compare(a.run, b.run); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ledger, b.ledger); c != 0 {
			return c
		}
		return cmp.Compare(a.request, b.request)
	})
	for _, key := range keys {
		r := requests[key]
		if !r.prepared {
			noteMissing("reservation_source_missing")
			continue
		}
		if r.queue == nil {
			noteMissing("queue_result_missing")
		}
		if r.input.SessionRun == "" || r.input.Session == 0 {
			noteMissing("original_session_unqualified")
			continue
		}
		ref := SessionRef{Run: r.input.SessionRun, Ordinal: r.input.Session}
		session := sessions[ref]
		if session == nil || !session.origin {
			noteMissing("session_origin_missing")
		} else if session.peer != r.input.Peer {
			return inconsistent("reservation_session_peer_changed")
		}
		if r.frame != nil {
			b := r.frame
			peer, known := peers[key.run][b.PeerIdx]
			if !known {
				noteMissing("frame_peer_missing")
			} else if peer != r.input.Peer {
				return inconsistent("frame_peer_changed")
			}
			if b.Session == nil {
				noteMissing("frame_session_missing")
			} else if *b.Session != ref {
				return inconsistent("frame_session_changed")
			}
			if b.Size > uint64(len(b.Payload)) {
				noteMissing("frame_payload_missing")
			} else if b.Code != r.input.Code || types.Hash(sha256.Sum256(b.Payload)) != r.input.PayloadSHA256 || codec.DedupKey(b.Payload) != r.input.Key {
				return inconsistent("frame_payload_changed")
			}
			if r.queue != nil && *r.queue != transport.Queued {
				return inconsistent("rejected_queue_has_write")
			}
			if b.Write != transport.WriteOK && b.Write != transport.WriteError {
				noteMissing("physical_write_result_missing")
			}
		}
		if r.queue != nil && *r.queue != transport.Queued {
			if r.complete != nil {
				return inconsistent("rejected_queue_has_receipt")
			}
			continue // A rejected request promises no functional callback.
		}
		if r.complete != nil {
			switch r.complete.Result {
			case transport.LocalWriteOK, transport.LocalWriteError:
				if r.frame == nil {
					noteMissing("physical_write_missing")
					continue
				}
				want := transport.WriteOK
				if r.complete.Result == transport.LocalWriteError {
					want = transport.WriteError
				}
				if r.frame.Write != want {
					return inconsistent("receipt_result_changed")
				}
				report.Writes++
			case transport.LocalWriteCancelled:
				if session == nil || !session.ended {
					noteMissing("session_end_missing")
				}
			}
		} else if r.retired {
			// Retirement by ledger Close does not itself prove stream closure.
			// Without a terminal receipt, raw sources remain a readable prefix.
			noteMissing("terminal_receipt_missing")
		} else if r.queue == nil || *r.queue == transport.Queued {
			noteMissing("write_pending")
		}
	}
	if missing != "" {
		return unavailable(missing)
	}
	if report.Reservations == 0 {
		return unavailable("no_write_reservations")
	}
	report.Status = "consistent"
	return report, nil
}
