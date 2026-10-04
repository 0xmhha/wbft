package transport

import (
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// FrameObserver receives the consensus frames an adapter carries and the
// lives of its peer streams, for the message journal (observe.md 3 and
// 11.3). The adapter calls it from its read and write loops; the calls must
// not block and must not keep payload beyond the call unless the adapter
// never reuses it.
type FrameObserver interface {
	// Received reports a consensus frame read from peer, with the length
	// of its payload on the wire, the payload (before the frame stage
	// unwraps it; nil when the adapter did not read it, for a frame over
	// the size limit) and what the adapter did with it: one of the Offer
	// values.
	Received(peer types.Address, code uint64, size int, payload []byte, offer string)
	// Wrote reports a consensus frame the adapter tried to write to peer:
	// WriteOK or WriteError.
	Wrote(peer types.Address, code uint64, payload []byte, write string)
	// Attached reports that the istanbul stream of peer was attached;
	// remote is the network address of the connection.
	Attached(peer types.Address, remote string)
	// Closed reports that the istanbul stream of peer was closed.
	Closed(peer types.Address, reason string)
}

// Observed is implemented by a transport that reports its frames. The node
// installs its observer before it connects the receiver.
type Observed interface {
	SetFrameObserver(o FrameObserver)
}

// What happened to a received frame (journal msg.offer).
const (
	OfferQueued          = "queued"           // offered to the receiver and queued
	OfferQueueFull       = "queue_full"       // the receiver's queue for the peer was full
	OfferFrameIgnore     = "frame_ignore"     // dropped by the frame stage
	OfferFrameDisconnect = "frame_disconnect" // the frame stage closed the connection
)

// Results of a frame write (journal msg.write).
const (
	WriteOK          = "ok"
	WriteError       = "error"
	WriteNotAttached = "not_attached" // the peer had no stream; nothing was written
)

// CauseSender is implemented by a transport that records why a message is
// sent (the journal's msg.cause, R-01 frame.cause) and to which peers it was
// not sent. Dedup uses it instead of Send when the transport has it.
type CauseSender interface {
	// SendCause is Send with the cause of the send.
	SendCause(peers []types.Address, code uint64, payload []byte, cause event.SendCause) []SendResult
	// Suppressed reports a send to peer that was left out because the
	// peer's recent cache holds the message (reason SuppressRecentCache).
	Suppressed(peer types.Address, code uint64, payload []byte, cause event.SendCause, reason string)
}

// SuppressRecentCache is the reason of a send left out because the peer's
// recent cache holds the message (R-01 send_suppressed.reason).
const SuppressRecentCache = "peer_recent_cache"
