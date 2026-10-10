package transport

import (
	"time"

	"github.com/0xmhha/wbft/types"
)

// Transport is the consensus message transport. It is implemented by the
// application's istanbul/100 adapter; peer addresses are the addresses of
// the peers' node keys.
type Transport interface {
	// Send queues payload under code for each peer and returns at once, one
	// result per peer in the order of peers.
	Send(peers []types.Address, code uint64, payload []byte) []SendResult
	// SetReceiver installs the inbound sink. The adapter's per-peer read loop
	// calls Offer for every frame with a code from 0x11 to 0x15 that
	// DecodeFrame delivers.
	SetReceiver(r Receiver)
	// PeerEvents reports peers whose istanbul stream was attached or
	// detached.
	PeerEvents() <-chan PeerEvent
	// Peers returns the peers whose istanbul stream is attached.
	Peers() []PeerInfo
	// Disconnect closes the connection to peer; reason is one of the Close
	// causes when the caller has one.
	Disconnect(peer types.Address, reason string)
}

// Receiver takes inbound messages. Offer never blocks; false means the
// message was dropped because the queue of that peer is full.
type Receiver interface {
	Offer(in Inbound) bool
}

// Inbound is one received message after the frame stage: data is the payload
// of codes 0x12 .. 0x15 and the unwrapped payload of 0x11.
type Inbound struct {
	Peer     types.Address
	Code     uint64
	Payload  []byte
	RecvMono time.Duration
}

// PeerInfo describes an attached peer.
type PeerInfo struct {
	Addr            types.Address
	Caps            []string
	Static, Trusted bool
	ConnectedSince  time.Time
}

// PeerEvent reports that the istanbul stream of a peer was attached or
// detached.
type PeerEvent struct {
	Addr     types.Address
	Attached bool
}

// SendResult is the result of queueing a message for one peer.
type SendResult uint8

// Send results.
const (
	Queued      SendResult = iota // queued for writing
	NotAttached                   // the peer has no istanbul stream yet
	QueueFull                     // the send queue of the peer is full
)
