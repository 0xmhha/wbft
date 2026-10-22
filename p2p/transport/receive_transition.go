package transport

import (
	"crypto/sha256"
	"slices"

	"github.com/0xmhha/wbft/types"
)

// ReceiveAction identifies an actual checking-ledger operation. It is separate
// from read-loop frame observations and never substitutes for core validation.
type ReceiveAction uint8

const (
	ReceiveLedgerStart ReceiveAction = iota + 1
	ReceiveCheckPrepare
	ReceiveCheckAccept
	ReceiveCheckCancel
	ReceiveKnownInspect
	ReceiveRecentInspect
	ReceivePendingPrune
	ReceiveLedgerClose
)

// ReceiveAcceptSource locates the direct/self ACCEPT selected by the runner.
// It is optional observation metadata. Consumers must independently check the
// original core step/output and capture before treating this as source proof.
type ReceiveAcceptSource struct {
	EngineRun, Step, Output uint64
	Via                     string
}

// ReceiveTransition contains value metadata for one mutex-ordered call. Scope
// and stream numbers are observations, never cache or validator capabilities.
// Request names the original successful Prepare sequence in this ledger.
// Known on Accept is membership before the successful mutation; Recent reports
// registration there. Inspection actions report their actual lookup result.
type ReceiveTransition struct {
	Ledger, Sequence                    uint64
	Action                              ReceiveAction
	Request, Scope                      uint64
	Input                               WriteIdentity
	Checked                             WriteIdentity
	Origin                              ReceiveOrigin
	CheckedOrigin                       ReceiveOrigin
	Source                              ReceiveAcceptSource
	Decision                            ReceiveDecision
	Owned, Matched, ScopeActive, Closed bool
	Known, Recent, Released             bool
	PendingBefore, PendingAfter         uint64
	Pruned                              []uint64
	PendingLimit, PerPeerLimit          uint64
	KeyWithCode                         bool
}

// ReceiveTransitionObserver runs after the functional mutex is released.
// Implementations must be concurrency safe, return promptly and report drops.
// Concurrent delivery may be out of order; Sequence preserves mutex ordering.
type ReceiveTransitionObserver interface {
	ObserveReceiveTransition(ReceiveTransition)
}

func (s *ValidationScope) ObservationID() uint64 {
	if s == nil {
		return 0
	}
	return s.lifetime.ObservationID()
}

func (l *ReceiveLedger) transitionReceive(action ReceiveAction) ReceiveTransition {
	if l.opt.Trace == nil {
		return ReceiveTransition{}
	}
	if l.traceSequence != ^uint64(0) {
		l.traceSequence++
	} else {
		l.traceExhausted = true
	}
	sequence := l.traceSequence
	if l.traceExhausted {
		sequence = 0
	}
	return ReceiveTransition{Ledger: l.observation, Sequence: sequence, Action: action, PendingBefore: uint64(len(l.pending)), Closed: l.closed}
}
func (l *ReceiveLedger) observedReceiveUnlock(t *ReceiveTransition) {
	if l.opt.Trace != nil {
		t.PendingAfter = uint64(len(l.pending))
		t.Closed = l.closed
	}
	l.mu.Unlock()
	if l.opt.Trace != nil {
		slices.Sort(t.Pruned)
		l.opt.Trace.ObserveReceiveTransition(*t)
	}
}
func (l *ReceiveLedger) receiveIdentity(in Inbound, key receiveKey) WriteIdentity {
	return WriteIdentity{Peer: in.Peer, Session: in.Stream.ObservationID(), Code: in.Code, Key: key.key.payload, PayloadSHA256: sha256.Sum256(in.Payload)}
}
func (l *ReceiveLedger) receiveTicketIdentity(t *ReceiveTransition, ticket ReceiveTicket) {
	if l.opt.Trace == nil {
		return
	}
	if r := ticket.reservation; r != nil && r.owner == l {
		t.Request = r.observation
		t.Scope = r.scope.ObservationID()
		t.ScopeActive = r.scope.Active()
		t.Origin = r.origin
		t.Input = WriteIdentity{Peer: r.peer, Session: r.stream, Code: r.code, Key: r.key.key.payload, PayloadSHA256: r.payload}
	}
}

func normalizedAcceptSource(source ReceiveAcceptSource) ReceiveAcceptSource {
	if source.EngineRun == 0 || source.Step == 0 || source.Output == 0 || source.Via != "direct" && source.Via != "self" {
		return ReceiveAcceptSource{}
	}
	return source
}

// ReceiveKnownInspect has no peer/stream source because Known is scoped only
// by the checking context and code/key. Zero hashes/identities stay unavailable.
func receiveLookupIdentity(peer types.Address, code uint64, key receiveKey, payload []byte) WriteIdentity {
	return WriteIdentity{Peer: peer, Code: code, Key: key.key.payload, PayloadSHA256: sha256.Sum256(payload)}
}
