package node

import (
	"sync"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/runner"
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
	offset uint64 // wire code offset (Identity.WireOffset)

	mu    sync.Mutex
	index map[types.Address]uint32
}

var _ transport.FrameObserver = (*frameRecorder)(nil)

// stampClock is the part of runner.Clock that stamps records.
type stampClock interface {
	Now() time.Time
	Mono() time.Duration
}

var _ stampClock = runner.Clock(nil)

func newFrameRecorder(jw journal.Writer, clock stampClock, offset uint64) *frameRecorder {
	return &frameRecorder{jw: jw, clock: clock, offset: offset, index: map[types.Address]uint32{}}
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
func (f *frameRecorder) Received(peer types.Address, code uint64, payload []byte, offer string) {
	m := f.msg(journal.In, peer, code, payload)
	m.Offer = offer
	f.jw.Put(journal.Record{Body: m})
}

// Wrote implements transport.FrameObserver.
func (f *frameRecorder) Wrote(peer types.Address, code uint64, payload []byte, write string) {
	m := f.msg(journal.Out, peer, code, payload)
	m.Write = write
	f.jw.Put(journal.Record{Body: m})
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
// error. The transport reports the writes it attempts itself.
type recordedTransport struct {
	transport.Transport
	rec *frameRecorder
}

func (t recordedTransport) Send(peers []types.Address, code uint64, payload []byte) []transport.SendResult {
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
