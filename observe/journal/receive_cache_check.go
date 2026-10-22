package journal

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// ReceiveCacheCheckLimits bound this offline check's state and ordering buffer.
// They are inspection limits, not a node operating budget or payload/heap cap.
type ReceiveCacheCheckLimits struct{ Records, Ledgers, Reordered uint64 }

// ReceiveCacheCheck separates transition consistency from physical provenance.
// A consistent trace is never a claim of remote delivery, verified core ACCEPT,
// or functional runtime replay. Immutable context metadata is compared, but its
// authority hashes are not source-authenticated here. PhysicalStatus remains unavailable until those
// independent sources are linked and checked by a physical-source consumer.
type ReceiveCacheCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	PhysicalStatus string `json:"physical_status"`
	Ledgers        uint64 `json:"ledgers,string"`
	Transitions    uint64 `json:"transitions,string"`
}

var ErrReceiveCacheHistory = errors.New("journal: inconsistent receive-cache history")

type receiveCacheOwner struct {
	run    string
	ledger uint64
}
type receiveCacheProfile struct {
	limits   transport.CachePolicyLimits
	declared bool
}
type receiveModelKey struct {
	scope, code uint64
	key         types.Hash
}
type receiveModelPeer struct {
	peer types.Address
	keys []receiveModelKey
}
type receiveModelRequest struct {
	scope  uint64
	input  transport.WriteIdentity
	origin transport.ReceiveOrigin
}
type receiveScopeOwner struct {
	run   string
	scope uint64
}
type receiveModelContext struct {
	known bool
	value transport.ValidationContext
}
type receiveCacheModel struct {
	next              uint64
	closed            bool
	limits            transport.CachePolicyLimits
	pending, requests map[uint64]receiveModelRequest
	known             []receiveModelKey
	peers             []receiveModelPeer
	buffered          map[uint64]transport.ReceiveTransition
}

// CheckReceiveCacheTransitions independently rebuilds pending checks and scoped known/recent caches
// from observations. It uses ordered slices rather than the runtime's LRU or
// ledger primitives. Concurrency may reorder callback delivery; a bounded
// per-ledger buffer restores only explicitly numbered operations. Missing data
// is unavailable, and contradictory retained data returns ErrReceiveCacheHistory.
// The caller owns records; this function does not read or modify live servers.
func CheckReceiveCacheTransitions(records []Record, limits ReceiveCacheCheckLimits) (ReceiveCacheCheck, error) {
	report := ReceiveCacheCheck{Status: "unavailable", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (ReceiveCacheCheck, error) {
		report.Status = "unavailable"
		report.Reason = reason
		return report, nil
	}
	inconsistent := func(reason string) (ReceiveCacheCheck, error) {
		report.Status = "inconsistent"
		report.Reason = reason
		return report, fmt.Errorf("%w: %s", ErrReceiveCacheHistory, reason)
	}
	if limits.Records == 0 || limits.Ledgers == 0 || limits.Reordered == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	profiles := make(map[string]receiveCacheProfile)
	models := make(map[receiveCacheOwner]*receiveCacheModel)
	contexts := make(map[receiveScopeOwner]receiveModelContext)
	currentRun := ""
	for _, record := range records {
		switch body := record.Body.(type) {
		case *SegmentRec:
			currentRun = body.Run
			profile := receiveCacheProfile{}
			if body.Core.CachePolicy != nil {
				if currentRun == "" {
					return unavailable("writer_run_missing")
				}
				if err := body.Core.CachePolicy.Validate(); err != nil {
					return unavailable("unsupported_profile")
				}
				profile = receiveCacheProfile{limits: body.Core.CachePolicy.Limits, declared: true}
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
				if kind.Count > 0 && (kind.Kind == uint64(KindReceiveCache) || kind.Kind == 0) {
					return unavailable("receive_cache_gap")
				}
			}
		case *ReceiveCacheRec:
			profile, ok := profiles[currentRun]
			if currentRun == "" || !ok || !profile.declared {
				return unavailable("profile_or_writer_missing")
			}
			t := body.Transition
			if body.Mono < 0 || !validReceiveTransition(t) {
				return inconsistent("invalid_transition_shape")
			}
			if t.Scope != 0 {
				identity := receiveScopeOwner{run: currentRun, scope: t.Scope}
				value := receiveModelContext{known: t.ContextKnown, value: t.Context}
				if previous, ok := contexts[identity]; ok && previous != value {
					return inconsistent("scope_context_changed")
				}
				contexts[identity] = value
			}
			owner := receiveCacheOwner{run: currentRun, ledger: t.Ledger}
			model := models[owner]
			if model == nil {
				if uint64(len(models)) >= limits.Ledgers {
					return unavailable("ledger_limit")
				}
				model = &receiveCacheModel{next: 1, limits: profile.limits, pending: make(map[uint64]receiveModelRequest), requests: make(map[uint64]receiveModelRequest), buffered: make(map[uint64]transport.ReceiveTransition)}
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
		return unavailable("no_receive_cache_trace")
	}
	for _, model := range models {
		if len(model.buffered) > 0 {
			return unavailable("missing_transition")
		}
	}
	report.Status = "consistent"
	report.Reason = "authority_and_physical_sources_not_checked"
	return report, nil
}

func (m *receiveCacheModel) modelKey(t transport.ReceiveTransition) receiveModelKey {
	return receiveModelKey{scope: t.Scope, code: t.Input.Code, key: t.Input.Key}
}
func (m *receiveCacheModel) knownContains(key receiveModelKey, touch bool) bool {
	for index, value := range m.known {
		if value == key {
			if touch {
				copy(m.known[index:], m.known[index+1:])
				m.known[len(m.known)-1] = value
			}
			return true
		}
	}
	return false
}
func (m *receiveCacheModel) registerKnown(key receiveModelKey) {
	if m.knownContains(key, true) {
		return
	}
	if len(m.known) == transport.InmemoryMessages {
		m.known = m.known[1:]
	}
	m.known = append(m.known, key)
}
func (m *receiveCacheModel) recentContains(peer types.Address, key receiveModelKey) bool {
	for _, entry := range m.peers {
		if entry.peer == peer {
			for _, value := range entry.keys {
				if value == key {
					return true
				}
			}
			return false
		}
	}
	return false
}
func (m *receiveCacheModel) registerRecent(peer types.Address, key receiveModelKey) {
	index := -1
	for i, entry := range m.peers {
		if entry.peer == peer {
			copy(m.peers[i:], m.peers[i+1:])
			m.peers[len(m.peers)-1] = entry
			index = len(m.peers) - 1
			break
		}
	}
	if index < 0 {
		if len(m.peers) == transport.InmemoryPeers {
			m.peers = m.peers[1:]
		}
		m.peers = append(m.peers, receiveModelPeer{peer: peer})
		index = len(m.peers) - 1
	}
	keys := m.peers[index].keys
	for i, value := range keys {
		if value == key {
			copy(keys[i:], keys[i+1:])
			keys[len(keys)-1] = value
			return
		}
	}
	if len(keys) == transport.InmemoryMessages {
		keys = keys[1:]
	}
	m.peers[index].keys = append(keys, key)
}
func (m *receiveCacheModel) apply(t transport.ReceiveTransition) error {
	fail := func(reason string) error {
		return fmt.Errorf("%s at ledger %d sequence %d", reason, t.Ledger, t.Sequence)
	}
	if t.PendingBefore != uint64(len(m.pending)) {
		return fail("pending_before_mismatch")
	}
	if t.Action == transport.ReceiveLedgerStart {
		if t.PendingLimit != m.limits.ReceivePending || t.PerPeerLimit != m.limits.ReceivePerPeer || !t.KeyWithCode {
			return fail("declaration_profile_mismatch")
		}
	} else {
		for _, request := range t.Pruned {
			if _, ok := m.pending[request]; !ok {
				return fail("unknown_pruned_request")
			}
			delete(m.pending, request)
		}
		key := m.modelKey(t)
		switch t.Action {
		case transport.ReceiveCheckPrepare:
			expected := transport.ReceiveUnavailable
			if !m.closed && t.ScopeActive {
				if m.knownContains(key, false) {
					expected = transport.ReceiveKnown
				} else {
					perPeer := uint64(0)
					for _, request := range m.pending {
						if request.input.Peer == t.Input.Peer {
							perPeer++
						}
					}
					expected = transport.ReceiveReserved
					if uint64(len(m.pending)) >= m.limits.ReceivePending || perPeer >= m.limits.ReceivePerPeer {
						expected = transport.ReceivePendingFull
					}
				}
			}
			if t.Decision != expected {
				return fail("prepare_decision_mismatch")
			}
			if expected == transport.ReceiveReserved {
				request := receiveModelRequest{scope: t.Scope, input: t.Input, origin: t.Origin}
				m.pending[t.Request] = request
				m.requests[t.Request] = request
			}
		case transport.ReceiveCheckAccept, transport.ReceiveCheckCancel:
			if t.Request != 0 {
				original, ok := m.requests[t.Request]
				if !ok || original != (receiveModelRequest{scope: t.Scope, input: t.Input, origin: t.Origin}) {
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
			if t.Action == transport.ReceiveCheckAccept && t.Matched && !m.closed && t.ScopeActive {
				known := m.knownContains(key, true)
				expected := transport.ReceiveRegistered
				if known {
					expected = transport.ReceiveDuplicate
				}
				if t.Known != known || t.Decision != expected {
					return fail("accepted_known_state_mismatch")
				}
				m.registerKnown(key)
				m.registerRecent(t.Input.Peer, key)
			}
		case transport.ReceiveKnownInspect:
			if t.Known != (t.ScopeActive && m.knownContains(key, false)) {
				return fail("known_lookup_mismatch")
			}
		case transport.ReceiveRecentInspect:
			if t.Recent != (t.ScopeActive && m.recentContains(t.Input.Peer, key)) {
				return fail("recent_lookup_mismatch")
			}
		case transport.ReceivePendingPrune:
		case transport.ReceiveLedgerClose:
			m.closed = true
			clear(m.pending)
			m.known = nil
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
