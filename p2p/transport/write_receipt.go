package transport

import (
	"sync/atomic"

	"github.com/0xmhha/wbft/types"
)

// WriteSession identifies one attached transport stream. Its lifetime is owned
// by the adapter, independently of recording observers. It is process-local
// metadata, never part of a wire message or a persisted consensus input.
// A session must not be copied after first use; transports pass its pointer.
type WriteSession struct{ active atomic.Bool }

// NewWriteSession starts a fresh stream lifetime, including on reconnection to
// the same peer address. A zero session is inactive.
func NewWriteSession() *WriteSession {
	s := new(WriteSession)
	s.active.Store(true)
	return s
}

// Active reports whether the transport still owns this attached stream.
func (s *WriteSession) Active() bool { return s != nil && s.active.Load() }

// Close ends a stream lifetime permanently. Only the transport owner calls it.
func (s *WriteSession) Close() {
	if s != nil {
		s.active.Store(false)
	}
}

// WritePeer binds a destination address to its exact attached stream.
type WritePeer struct {
	Addr    types.Address
	Session *WriteSession
}

// LocalWriteResult describes local completion, not remote receipt or execution.
type LocalWriteResult uint8

const (
	// LocalWriteOK means the adapter's actual WriteMsg returned successfully.
	LocalWriteOK LocalWriteResult = iota + 1
	// LocalWriteCancelled means the stream ended before completion was retained.
	LocalWriteCancelled
	// LocalWriteError means the adapter's actual WriteMsg returned an error.
	LocalWriteError
)

// WriteReceipt terminates one queued request. PayloadSHA256 identifies the
// exact bytes owned by that request; it is not a peer deduplication key.
type WriteReceipt struct {
	Target        WritePeer
	Code          uint64
	PayloadSHA256 types.Hash
	Result        LocalWriteResult
}

// WriteSender is an optional functional completion API. A transport that does
// not implement it cannot promise registration after actual local write.
//
// SendWrite freezes target's session and owns a copy of payload. A Queued result
// promises exactly one terminal callback, possibly before SendWrite returns.
// A rejected request has no callback. The callback runs without adapter locks
// and must return promptly. Closing the session cancels outstanding requests;
// a late write cannot issue a second receipt. Users must check session lifetime
// before updating state because completion and a normal close can race.
//
// attempt is optional recording metadata. Replacing or removing an observer
// never removes the functional receipt, changes its target, or revives a closed
// session. The existing Send API retains its queue-only semantics.
type WriteSender interface {
	WritePeers() []WritePeer
	SendWrite(target WritePeer, code uint64, payload []byte, attempt SendAttempt, done func(WriteReceipt)) SendResult
}
