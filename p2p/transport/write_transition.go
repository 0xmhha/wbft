package transport

import (
	"github.com/0xmhha/wbft/types"
	"slices"
)

// WriteAction identifies an actual functional ledger call. These observations
// are separate from legacy frame-cache operations and are not replay commands.
type WriteAction uint8

const (
	WriteStart WriteAction = iota + 1
	WritePrepare
	WriteQueueResult
	WriteComplete
	WriteAccept
	WritePrune
	WriteClose
)

// WriteIdentity contains only value metadata. Session is a process-local
// observation number, never a replacement for the original session pointer.
// SessionRun is the frozen first-writer qualification; an empty qualification
// must not be replaced with the current recording run.
type WriteIdentity struct {
	Peer          types.Address
	Session       uint64
	SessionRun    string
	Code          uint64
	Key           types.Hash
	PayloadSHA256 types.Hash
}

// WriteTransition is an immutable observation of one mutex-ordered call.
// Request refers to the successful Prepare sequence in this ledger. Pruned
// requests were reclaimed after their original sessions ended. No payload,
// pointer, signing material or remote-receipt claim is included.
//
// Sequence zero signals exhausted observation numbering. Observers must treat
// missing identities, gaps and unavailable physical provenance as incomplete
// evidence. This trace alone does not authenticate an adapter write or ACCEPT.
type WriteTransition struct {
	Ledger, Sequence            uint64
	Action                      WriteAction
	Request                     uint64
	Input                       WriteIdentity
	Receipt                     WriteIdentity
	Decision                    WriteDecision
	Queue                       SendResult
	Result                      LocalWriteResult
	Owned, Matched, Valid       bool
	Released, Registered        bool
	SessionActive, Closed       bool
	PendingBefore, PendingAfter uint64
	Pruned                      []uint64
	PendingLimit, PerPeerLimit  uint64
	KeyWithCode                 bool
}

// WriteTransitionObserver consumes observations after the functional mutex is
// released. Calls from concurrent operations may arrive out of sequence; their
// immutable Sequence gives the ledger order. Implementations must be safe for
// concurrent calls, return promptly, and report drops rather than invent gaps.
// Recording cannot cancel or replace a functional ticket or receipt.
type WriteTransitionObserver interface {
	ObserveWriteTransition(WriteTransition)
}

func (l *WriteLedger) transition(action WriteAction) WriteTransition {
	if l.opt.Trace == nil {
		return WriteTransition{}
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
	return WriteTransition{Ledger: l.observation, Sequence: sequence, Action: action, PendingBefore: uint64(len(l.pending)), Closed: l.closed}
}

func (l *WriteLedger) publish(t *WriteTransition) {
	if l.opt.Trace == nil {
		return
	}
	t.PendingAfter = uint64(len(l.pending))
	t.Closed = l.closed
}

func (l *WriteLedger) observedUnlock(t *WriteTransition) {
	l.publish(t)
	l.mu.Unlock()
	if l.opt.Trace != nil {
		slices.Sort(t.Pruned)
		l.opt.Trace.ObserveWriteTransition(*t)
	}
}

func (l *WriteLedger) identity(target WritePeer, code uint64, key writeKey, sha types.Hash) WriteIdentity {
	return WriteIdentity{Peer: target.Addr, Session: target.Session.ObservationID(), SessionRun: target.Session.ObservationRun(), Code: code, Key: key.payload, PayloadSHA256: sha}
}

func (l *WriteLedger) ticketIdentity(t *WriteTransition, ticket WriteTicket) {
	if l.opt.Trace == nil {
		return
	}
	if r := ticket.reservation; r != nil && r.owner == l {
		t.Request = r.observation
		t.Input = l.identity(r.target, r.code, r.key, r.payload)
		t.Input.SessionRun = r.streamRun
		t.SessionActive = r.target.Session.Active()
	}
}
