package transport

import (
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// AttemptOwner is an opaque recording lifetime. It is compared only inside
// the process and must never be serialized as an address or nonce.
// The nonzero size ensures distinct live owners have distinct pointers.
type AttemptOwner struct{ _ byte }

func NewAttemptOwner() *AttemptOwner { return &AttemptOwner{} }

// SendAttempt identifies one send call within its recording owner. All peers
// in the call share Sequence; the peer address distinguishes their attempts.
// Cache and Operation are either both zero (no cache proof) or both nonzero.
// This value is queue metadata, never part of the transmitted payload.
type SendAttempt struct {
	owner                      *AttemptOwner
	Sequence, Cache, Operation uint64
	Cause                      event.SendCause
}

func NewSendAttempt(owner *AttemptOwner, sequence, cache, operation uint64, cause event.SendCause) SendAttempt {
	if owner == nil || sequence == 0 || (cache == 0) != (operation == 0) {
		return SendAttempt{}
	}
	return SendAttempt{owner: owner, Sequence: sequence, Cache: cache, Operation: operation, Cause: cause}
}

func (a SendAttempt) OwnedBy(owner *AttemptOwner) bool {
	return owner != nil && a.owner == owner && a.Sequence != 0 && (a.Cache == 0) == (a.Operation == 0)
}

// AttemptSender preserves send metadata through the actual adapter queue.
// Implementations must freeze observer generation when they enqueue a frame
// and erase the attempt when that generation changes before its callback.
type AttemptSender interface {
	SendAttempt(peers []types.Address, code uint64, payload []byte, attempt SendAttempt) []SendResult
}

// AttemptObserver receives an exact queue attempt or its zero value when
// unavailable. A zero attempt must not fall back to a peer/key cause lookup.
// A nil interval means unavailable I/O timing, independently of the attempt.
type AttemptObserver interface {
	AttemptOwner() *AttemptOwner
	WroteAttempt(peer types.Address, code uint64, payload []byte, write string, attempt SendAttempt, interval *IOInterval)
}

// BindAttempt accepts only metadata owned by this observer's recording life.
func BindAttempt(o FrameObserver, attempt SendAttempt) SendAttempt {
	if a, ok := o.(AttemptObserver); ok && attempt.OwnedBy(a.AttemptOwner()) {
		return attempt
	}
	return SendAttempt{}
}

// ReportWroteAttempt keeps unavailable provenance explicit, including callbacks
// from an old queue that happen to have the new owner's peer and payload key.
func ReportWroteAttempt(o FrameObserver, peer types.Address, code uint64, payload []byte, write string, attempt SendAttempt, interval *IOInterval) {
	if o == nil {
		return
	}
	if a, ok := o.(AttemptObserver); ok {
		a.WroteAttempt(peer, code, payload, write, BindAttempt(o, attempt), interval)
	} else if interval != nil {
		ReportWroteIO(o, peer, code, payload, write, *interval)
	} else {
		o.Wrote(peer, code, payload, write)
	}
}
