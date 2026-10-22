package node

import (
	"sync"
	"sync/atomic"
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
	capture         atomic.Uint64
	attemptSequence atomic.Uint64
	cacheInstance   atomic.Uint64
	owner           *transport.AttemptOwner
	jw              journal.Writer
	clock           stampClock
	offset          uint64        // wire code offset (Identity.WireOffset)
	engine          func() string // engine state for received frames; nil: unknown

	mu    sync.Mutex
	index map[types.Address]uint32
	// causes holds the cause of a send until the transport reports the
	// write; it is cleared when it grows past maxPendingCauses (writes
	// that never come, on a closed connection).
	causes          map[sendKey]event.SendCause
	ambiguous       map[sendKey]bool
	legacyExhausted bool
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
var _ transport.IOObserver = (*frameRecorder)(nil)

// stampClock is the part of runner.Clock that stamps records.
type stampClock interface {
	Now() time.Time
	Mono() time.Duration
}

var _ stampClock = runner.Clock(nil)

func newFrameRecorder(jw journal.Writer, clock stampClock, offset uint64) *frameRecorder {
	return &frameRecorder{jw: jw, clock: clock, offset: offset, index: map[types.Address]uint32{}, causes: map[sendKey]event.SendCause{}, owner: transport.NewAttemptOwner(), ambiguous: map[sendKey]bool{},
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
// Capture saturates instead of reusing a number in this writer run. Zero is
// unavailable metadata and never grants functional input ownership.
func (f *frameRecorder) Capture() uint64 {
	for {
		previous := f.capture.Load()
		if previous == ^uint64(0) {
			return 0
		}
		if f.capture.CompareAndSwap(previous, previous+1) {
			return previous + 1
		}
	}
}
func (f *frameRecorder) CaptureRun() string {
	if source, ok := f.jw.(interface{ CaptureRun() string }); ok {
		return source.CaptureRun()
	}
	return ""
}
func (f *frameRecorder) Moment() transport.IOMoment {
	return transport.IOMoment{Mono: f.clock.Mono(), WallNs: f.clock.Now().UnixNano()}
}

func recordedIO(interval transport.IOInterval) *journal.IOInterval {
	return &journal.IOInterval{StartMono: interval.Start.Mono, StartWallNs: interval.Start.WallNs, EndMono: interval.End.Mono, EndWallNs: interval.End.WallNs}
}

func (f *frameRecorder) ReceivedIO(peer types.Address, code uint64, size int, payload []byte, offer string, capture uint64, interval transport.IOInterval) {
	f.received(peer, code, size, payload, offer, capture, recordedIO(interval))
}
func (f *frameRecorder) Received(peer types.Address, code uint64, size int, payload []byte, offer string) {
	f.ReceivedCapture(peer, code, size, payload, offer, 0)
}
func (f *frameRecorder) ReceivedCapture(peer types.Address, code uint64, size int, payload []byte, offer string, capture uint64) {
	f.received(peer, code, size, payload, offer, capture, nil)
}
func (f *frameRecorder) received(peer types.Address, code uint64, size int, payload []byte, offer string, capture uint64, io *journal.IOInterval) {
	m := f.msg(journal.In, peer, code, payload)
	m.IO = io
	m.Offer = offer
	m.Capture = capture
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
	f.wrote(peer, code, payload, write, nil)
}
func (f *frameRecorder) WroteIO(peer types.Address, code uint64, payload []byte, write string, interval transport.IOInterval) {
	f.wrote(peer, code, payload, write, recordedIO(interval))
}
func (f *frameRecorder) wrote(peer types.Address, code uint64, payload []byte, write string, io *journal.IOInterval) {
	m := f.msg(journal.Out, peer, code, payload)
	m.IO = io
	m.Write = write
	k := sendKey{peer, m.DedupKey}
	f.mu.Lock()
	if !f.legacyExhausted && !f.ambiguous[k] {
		m.Cause = f.causes[k]
	}
	delete(f.causes, k)
	f.mu.Unlock()
	f.jw.Put(journal.Record{Body: m})
}

// expect keeps the cause of a send to peers until their writes are
// reported.
func (f *frameRecorder) expect(peers []types.Address, key types.Hash, cause event.SendCause) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.legacyExhausted {
		return
	}
	if len(f.causes)+len(f.ambiguous) > maxPendingCauses {
		clear(f.causes)
		clear(f.ambiguous)
		f.legacyExhausted = true
		return
	}
	for _, p := range peers {
		k := sendKey{p, key}
		if _, pending := f.causes[k]; pending {
			f.ambiguous[k] = true
		}
		f.causes[k] = cause
	}
}

func (f *frameRecorder) AttemptOwner() *transport.AttemptOwner { return f.owner }

func (f *frameRecorder) WroteAttempt(peer types.Address, code uint64, payload []byte, write string, attempt transport.SendAttempt, interval *transport.IOInterval) {
	m := f.msg(journal.Out, peer, code, payload)
	m.Write = write
	if interval != nil {
		m.IO = recordedIO(*interval)
	}
	if attempt.OwnedBy(f.owner) {
		m.Cause = attempt.Cause
		m.Attempt = &journal.SendAttempt{Sequence: attempt.Sequence, Cache: attempt.Cache, Operation: attempt.Operation}
	}
	// An exact-attempt callback never consults the legacy peer/key map.
	f.jw.Put(journal.Record{Body: m})
}

// Attached implements transport.FrameObserver.
func (f *frameRecorder) Attached(peer types.Address, remote string) {
	f.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: f.peerIdx(peer), Addr: peer, Remote: remote, Event: "attached"}})
}

// Closed implements transport.FrameObserver, for a transport that does not
// say who closed the stream.
func (f *frameRecorder) Closed(peer types.Address, reason string) {
	f.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: f.peerIdx(peer), Addr: peer, Event: "closed", Reason: reason}})
}

// ClosedWith implements transport.CloseObserver.
func (f *frameRecorder) ClosedWith(peer types.Address, c transport.Close) {
	f.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: f.peerIdx(peer), Addr: peer, Event: "closed", Reason: c.Reason,
		By: c.By, Cause: c.Cause}})
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
	return t.SendCache(peers, code, payload, cause, 0, 0)
}

func (t recordedTransport) SendCache(peers []types.Address, code uint64, payload []byte, cause event.SendCause, instance, operation uint64) []transport.SendResult {
	if sender, ok := t.Transport.(transport.AttemptSender); ok {
		attempt := transport.NewSendAttempt(t.rec.owner, t.rec.attemptSequence.Add(1), instance, operation, cause)
		res := sender.SendAttempt(peers, code, payload, attempt)
		for i, r := range res {
			switch r {
			case transport.NotAttached:
				t.rec.WroteAttempt(peers[i], code, payload, transport.WriteNotAttached, attempt, nil)
			case transport.QueueFull:
				t.rec.WroteAttempt(peers[i], code, payload, transport.WriteError, attempt, nil)
			}
		}
		return res
	}
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

func (t recordedTransport) BeginCache(self types.Address) uint64 {
	id := t.rec.cacheInstance.Add(1)
	t.rec.jw.Put(journal.Record{Body: &journal.CacheRec{Instance: id, Action: "begin", Self: self, PeerCapacity: transport.InmemoryPeers, MessageCapacity: transport.InmemoryMessages}})
	return id
}
func (t recordedTransport) CacheOperation(op transport.CacheOperation) {
	t.rec.jw.Put(journal.Record{Body: &journal.CacheRec{Instance: op.Instance, Sequence: op.Sequence, Action: op.Action, Peer: op.Peer, Code: op.Code, Key: op.Key, PayloadSHA256: op.PayloadSHA256, Cause: op.Cause, Known: op.Known, Recent: op.Recent, Available: op.Available, Candidates: op.Candidates, Targets: op.Targets, Suppressed: op.Suppressed, Mono: t.rec.clock.Mono(), WallNs: t.rec.clock.Now().UnixNano()}})
}
func (t recordedTransport) SuppressedCache(peer types.Address, _ uint64, payload []byte, cause event.SendCause, reason string, instance, operation uint64) {
	t.rec.jw.Put(journal.Record{Body: &journal.SuppressedRec{PeerIdx: t.rec.peerIdx(peer), DedupKey: codec.DedupKey(payload), Cause: cause, Reason: reason, Cache: instance, Operation: operation}})
}
