package transport

import "github.com/0xmhha/wbft/types"

// FrameObserver receives the consensus frames an adapter carries and the
// lives of its peer streams, for the message journal (observe.md 3 and
// 11.3). The adapter calls it from its read and write loops; the calls must
// not block and must not keep payload beyond the call unless the adapter
// never reuses it.
type FrameObserver interface {
	// Received reports a consensus frame read from peer, with its wire
	// payload (before the frame stage unwraps it) and what the adapter did
	// with it: one of the Offer values.
	Received(peer types.Address, code uint64, payload []byte, offer string)
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
