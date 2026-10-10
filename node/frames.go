package node

import (
	"sync"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// frameRecorder writes the frames and peer streams a transport reports as
// journal msg and peer records (observe.md 11.3). Peers are numbered in the
// order the recorder first sees them, from 1.
type frameRecorder struct {
	jw     journal.Writer
	clock  stampClock
	offset uint64        // wire code offset (Identity.WireOffset)
	engine func() string // engine state for received frames; nil: unknown

	mu    sync.Mutex
	index map[types.Address]uint32
	// causes holds the cause of a send until the transport reports the
	// write; it is cleared when it grows past maxPendingCauses (writes
	// that never come, on a closed connection).
	causes map[sendKey]event.SendCause
	// hits holds the dedup cache hits of the frame a peer's read loop is
	// offering, until the adapter reports that frame (Received follows
	// Offer in the same loop).
	hits map[types.Address]journal.DedupHits
}

// sendKey is one message to one peer.
type sendKey struct {
	peer types.Address
	key  types.Hash
}

// maxPendingCauses bounds the causes kept for writes not yet reported.
const maxPendingCauses = 1 << 14

var _ transport.FrameObserver = (*frameRecorder)(nil)

// stampClock is the part of runner.Clock that stamps records.
type stampClock interface {
	Now() time.Time
	Mono() time.Duration
}

var _ stampClock = runner.Clock(nil)

func newFrameRecorder(jw journal.Writer, clock stampClock, offset uint64) *frameRecorder {
	return &frameRecorder{jw: jw, clock: clock, offset: offset, index: map[types.Address]uint32{}, causes: map[sendKey]event.SendCause{},
		hits: map[types.Address]journal.DedupHits{}}
}

func (f *frameRecorder) peerIdx(peer types.Address) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.index[peer]
	if !ok {
		i = uint32(len(f.index) + 1)
		f.index[peer] = i
	}
	return i
}

func (f *frameRecorder) msg(dir string, peer types.Address, code uint64, payload []byte) *journal.MsgRec {
	return &journal.MsgRec{Dir: dir, PeerIdx: f.peerIdx(peer), Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano(),
		Code: code, WireCode: code + f.offset, Payload: payload, DedupKey: codec.DedupKey(payload)}
}

// Received implements transport.FrameObserver.
func (f *frameRecorder) Received(peer types.Address, code uint64, size int, payload []byte, offer string) {
	m := f.msg(journal.In, peer, code, payload)
	m.Offer = offer
	if f.engine != nil {
		m.Engine = f.engine()
	}
	f.mu.Lock()
	if h, ok := f.hits[peer]; ok {
		m.Dedup = &h
		delete(f.hits, peer)
	}
	f.mu.Unlock()
	if size > len(payload) { // the payload was not kept: its key is unknown
		m.Size, m.DedupKey = uint64(size), types.Hash{}
	}
	f.jw.Put(journal.Record{Body: m})
}

// inbound keeps the dedup cache hits of the frame peer's read loop is
// offering (transport.DedupOptions.Inbound).
func (f *frameRecorder) inbound(peer types.Address, known, peerRecent bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[peer] = journal.DedupHits{Known: known, PeerRecent: peerRecent}
}

// Wrote implements transport.FrameObserver.
func (f *frameRecorder) Wrote(peer types.Address, code uint64, payload []byte, write string) {
	m := f.msg(journal.Out, peer, code, payload)
	m.Write = write
	k := sendKey{peer, m.DedupKey}
	f.mu.Lock()
	m.Cause = f.causes[k]
	delete(f.causes, k)
	f.mu.Unlock()
	f.jw.Put(journal.Record{Body: m})
}

// expect keeps the cause of a send to peers until their writes are
// reported.
func (f *frameRecorder) expect(peers []types.Address, key types.Hash, cause event.SendCause) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.causes) > maxPendingCauses {
		clear(f.causes)
	}
	for _, p := range peers {
		f.causes[sendKey{p, key}] = cause
	}
}

// Attached implements transport.FrameObserver.
func (f *frameRecorder) Attached(peer types.Address, remote string) {
	f.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: f.peerIdx(peer), Addr: peer, Remote: remote, Event: "attached"}})
}

// Closed implements transport.FrameObserver.
func (f *frameRecorder) Closed(peer types.Address, reason string) {
	f.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: f.peerIdx(peer), Addr: peer, Event: "closed", Reason: reason}})
}

// recordedTransport records the sends a transport does not attempt: a peer
// without a stream is written as not_attached, and a full send queue as an
// error. The transport reports the writes it attempts itself. It keeps the
// cause Dedup gives (transport.CauseSender) for those writes, and records
// the sends Dedup left out as suppressed.
type recordedTransport struct {
	transport.Transport
	rec *frameRecorder
}

var _ transport.CauseSender = recordedTransport{}

func (t recordedTransport) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
	return t.SendCause(peers, code, payload, "")
}

// SendCause implements transport.CauseSender.
func (t recordedTransport) SendCause(peers []types.Address, code uint64, payload []byte, cause event.SendCause) []transport.SendResult {
	if cause != "" {
		t.rec.expect(peers, codec.DedupKey(payload), cause)
	}
	res := t.Transport.Send(peers, code, payload)
	for i, r := range res {
		switch r {
		case transport.NotAttached:
			t.rec.Wrote(peers[i], code, payload, transport.WriteNotAttached)
		case transport.QueueFull:
			t.rec.Wrote(peers[i], code, payload, transport.WriteError)
		}
	}
	return res
}

// Suppressed implements transport.CauseSender.
func (t recordedTransport) Suppressed(peer types.Address, _ uint64, payload []byte, cause event.SendCause, reason string) {
	t.rec.jw.Put(journal.Record{Body: &journal.SuppressedRec{PeerIdx: t.rec.peerIdx(peer), DedupKey: codec.DedupKey(payload),
		Cause: cause, Reason: reason}})
}
