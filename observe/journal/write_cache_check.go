package journal

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// WriteCacheCheckLimits bound this offline check's state and ordering buffer.
// They are inspection limits, not a node operating budget or payload/heap cap.
type WriteCacheCheckLimits struct{ Records, Ledgers, Reordered uint64 }

// WriteCacheCheck separates transition consistency from physical provenance.
// A consistent trace is never a claim of remote delivery, verified core ACCEPT,
// or functional runtime replay. PhysicalStatus remains unavailable until those
// independent sources are linked and checked by a physical-source consumer.
type WriteCacheCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	PhysicalStatus string `json:"physical_status"`
	Ledgers        uint64 `json:"ledgers,string"`
	Transitions    uint64 `json:"transitions,string"`
}

var ErrWriteCacheHistory = errors.New("journal: inconsistent write-cache history")

type writeCacheOwner struct {
	run    string
	ledger uint64
}
type writeCacheProfile struct {
	limits   transport.CachePolicyLimits
	declared bool
}
type writeModelKey struct {
	code uint64
	key  types.Hash
}
type writeModelPeer struct {
	peer types.Address
	keys []writeModelKey
}
type writeCacheModel struct {
	next     uint64
	closed   bool
	limits   transport.CachePolicyLimits
	pending  map[uint64]transport.WriteIdentity
	requests map[uint64]transport.WriteIdentity
	peers    []writeModelPeer
	buffered map[uint64]transport.WriteTransition
}

// CheckWriteCacheTransitions independently rebuilds pending and recent caches
// from observations. It uses ordered slices rather than the runtime's LRU or
// ledger primitives. Concurrency may reorder callback delivery; a bounded
// per-ledger buffer restores only explicitly numbered operations. Missing data
// is unavailable, and contradictory retained data returns ErrWriteCacheHistory.
// The caller owns records; this function does not read or modify live servers.
func CheckWriteCacheTransitions(records []Record, limits WriteCacheCheckLimits) (WriteCacheCheck, error) {
	report := WriteCacheCheck{Status: "unavailable", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (WriteCacheCheck, error) {
		report.Status = "unavailable"
		report.Reason = reason
		return report, nil
	}
	inconsistent := func(reason string) (WriteCacheCheck, error) {
		report.Status = "inconsistent"
		report.Reason = reason
		return report, fmt.Errorf("%w: %s", ErrWriteCacheHistory, reason)
	}
	if limits.Records == 0 || limits.Ledgers == 0 || limits.Reordered == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	profiles := make(map[string]writeCacheProfile)
	models := make(map[writeCacheOwner]*writeCacheModel)
	currentRun := ""
	for _, record := range records {
		switch body := record.Body.(type) {
		case *SegmentRec:
			currentRun = body.Run
			profile := writeCacheProfile{}
			if body.Core.CachePolicy != nil {
				if currentRun == "" {
					return unavailable("writer_run_missing")
				}
				if err := body.Core.CachePolicy.Validate(); err != nil {
					return unavailable("unsupported_profile")
				}
				profile = writeCacheProfile{limits: body.Core.CachePolicy.Limits, declared: true}
			}
			if old, ok := profiles[currentRun]; ok && old != profile {
				return inconsistent("writer_profile_changed")
			}
			profiles[currentRun] = profile
		case *GapRec:
			if body.Dropped > 0 && len(body.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, kind := range body.ByKind {
				if kind.Count > 0 && (kind.Kind == uint64(KindWriteCache) || kind.Kind == 0) {
					return unavailable("write_cache_gap")
				}
			}
		case *WriteCacheRec:
			profile, ok := profiles[currentRun]
			if currentRun == "" || !ok || !profile.declared {
				return unavailable("profile_or_writer_missing")
			}
			t := body.Transition
			if body.Mono < 0 || !validWriteTransition(t) {
				return inconsistent("invalid_transition_shape")
			}
			owner := writeCacheOwner{run: currentRun, ledger: t.Ledger}
			model := models[owner]
			if model == nil {
				if uint64(len(models)) >= limits.Ledgers {
					return unavailable("ledger_limit")
				}
				model = &writeCacheModel{next: 1, limits: profile.limits, pending: make(map[uint64]transport.WriteIdentity), requests: make(map[uint64]transport.WriteIdentity), buffered: make(map[uint64]transport.WriteTransition)}
				models[owner] = model
				report.Ledgers++
			}
			if t.Sequence < model.next || model.next == 0 {
				return inconsistent("duplicate_or_exhausted_sequence")
			}
			if t.Sequence > model.next {
				if _, ok := model.buffered[t.Sequence]; ok {
					return inconsistent("duplicate_buffered_sequence")
				}
				if uint64(len(model.buffered)) >= limits.Reordered {
					return unavailable("reorder_limit")
				}
				model.buffered[t.Sequence] = t
				continue
			}
			for {
				if err := model.apply(t); err != nil {
					return inconsistent(err.Error())
				}
				report.Transitions++
				if model.next == ^uint64(0) {
					model.next = 0
					break
				}
				model.next++
				next, ok := model.buffered[model.next]
				if !ok {
					break
				}
				delete(model.buffered, model.next)
				t = next
			}
		}
	}
	if len(models) == 0 {
		return unavailable("no_write_cache_trace")
	}
	for _, model := range models {
		if len(model.buffered) > 0 {
			return unavailable("missing_transition")
		}
	}
	report.Status = "consistent"
	report.Reason = "physical_sources_not_checked"
	return report, nil
}

func (m *writeCacheModel) modelKey(in transport.WriteIdentity) writeModelKey {
	return writeModelKey{code: in.Code, key: in.Key}
}

// peer and key slices are oldest first. A lookup touches an existing peer even
// on a message miss; only successful registration creates a missing peer.
func (m *writeCacheModel) touchPeer(peer types.Address, create bool) int {
	for index, entry := range m.peers {
		if entry.peer == peer {
			copy(m.peers[index:], m.peers[index+1:])
			m.peers[len(m.peers)-1] = entry
			return len(m.peers) - 1
		}
	}
	if !create {
		return -1
	}
	if len(m.peers) == transport.InmemoryPeers {
		m.peers = m.peers[1:]
	}
	m.peers = append(m.peers, writeModelPeer{peer: peer})
	return len(m.peers) - 1
}
func (m *writeCacheModel) recent(in transport.WriteIdentity) bool {
	index := m.touchPeer(in.Peer, false)
	if index < 0 {
		return false
	}
	key := m.modelKey(in)
	keys := m.peers[index].keys
	for i, k := range keys {
		if k == key {
			copy(keys[i:], keys[i+1:])
			keys[len(keys)-1] = k
			return true
		}
	}
	return false
}
func (m *writeCacheModel) register(in transport.WriteIdentity) {
	index := m.touchPeer(in.Peer, true)
	key := m.modelKey(in)
	keys := m.peers[index].keys
	for i, k := range keys {
		if k == key {
			copy(keys[i:], keys[i+1:])
			keys[len(keys)-1] = k
			return
		}
	}
	if len(keys) == transport.InmemoryMessages {
		keys = keys[1:]
	}
	m.peers[index].keys = append(keys, key)
}

func (m *writeCacheModel) apply(t transport.WriteTransition) error {
	fail := func(reason string) error {
		return fmt.Errorf("%s at ledger %d sequence %d", reason, t.Ledger, t.Sequence)
	}
	if t.PendingBefore != uint64(len(m.pending)) {
		return fail("pending_before_mismatch")
	}
	if t.Action == transport.WriteStart {
		if t.PendingLimit != m.limits.WritePending || t.PerPeerLimit != m.limits.WritePerPeer || !t.KeyWithCode {
			return fail("declaration_profile_mismatch")
		}
	} else {
		for _, request := range t.Pruned {
			if _, ok := m.pending[request]; !ok {
				return fail("unknown_pruned_request")
			}
			delete(m.pending, request)
		}
		switch t.Action {
		case transport.WritePrepare:
			expected := transport.WriteUnavailable
			if !m.closed && t.Valid && t.SessionActive {
				if m.recent(t.Input) {
					expected = transport.WriteAlreadyRecent
				} else {
					expected = transport.WriteReserved
					perPeer := uint64(0)
					for _, pending := range m.pending {
						if pending.Peer == t.Input.Peer {
							perPeer++
						}
						if pending.Peer == t.Input.Peer && pending.Session == t.Input.Session && m.modelKey(pending) == m.modelKey(t.Input) {
							expected = transport.WriteAlreadyPending
						}
					}
					if expected == transport.WriteReserved && (uint64(len(m.pending)) >= m.limits.WritePending || perPeer >= m.limits.WritePerPeer) {
						expected = transport.WritePendingFull
					}
				}
			}
			if t.Decision != expected {
				return fail("prepare_decision_mismatch")
			}
			if expected == transport.WriteReserved {
				m.pending[t.Request] = t.Input
				m.requests[t.Request] = t.Input
			}
		case transport.WriteQueueResult, transport.WriteComplete:
			if t.Request != 0 {
				original, ok := m.requests[t.Request]
				if !ok || original != t.Input {
					return fail("request_origin_mismatch")
				}
			}
			_, owned := m.pending[t.Request]
			if t.Owned != owned {
				return fail("request_ownership_mismatch")
			}
			if t.Released {
				delete(m.pending, t.Request)
			}
			if t.Registered {
				m.register(t.Input)
			}
		case transport.WriteAccept:
			if t.Registered {
				m.register(t.Input)
			}
		case transport.WritePrune:
		case transport.WriteClose:
			m.closed = true
			clear(m.pending)
			m.peers = nil
		default:
			return fail("unexpected_action")
		}
	}
	if t.Closed != m.closed {
		return fail("ledger_lifetime_mismatch")
	}
	if t.PendingAfter != uint64(len(m.pending)) {
		return fail("pending_after_mismatch")
	}
	return nil
}
