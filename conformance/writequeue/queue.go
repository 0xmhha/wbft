// Package writequeue models normal single-stream writes on a manual clock.
// Its receipts describe simulated local completion, never actual socket I/O.
// It is not enabled by the default consensus simulator or a replay policy.
package writequeue

import (
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Options declares queue entry capacity separately from the one active write.
// Durations are fixed service/link delays, not measurements of physical I/O.
type Options struct {
	Waiting   int
	WriteTime time.Duration
	LinkTime  time.Duration
}

// Queue owns exactly one stream. Calls and clock advancement must be serialized
// by the manual-clock driver. Callbacks may enqueue or close this queue.
// Closing suppresses pending arrivals on this stream, including completed
// writes; a successful receipt alone never promises remote arrival.
type Queue struct {
	clock   *manualclock.Clock
	target  transport.WritePeer
	opt     Options
	arrive  func(uint64, []byte)
	active  *request
	waiting []*request
	closed  bool
}

type request struct {
	code    uint64
	payload []byte
	receipt transport.WriteReceipt
	done    func(transport.WriteReceipt)
	timer   *manualclock.Event
}

var _ transport.WriteSender = (*Queue)(nil)

// New creates and owns a fresh stream even when a previous queue used peer.
// Capacity bounds waiting entries, not bytes or process heap. arrive is called
// only after both write service and link delay on the original active stream.
func New(clock *manualclock.Clock, peer types.Address, opt Options, arrive func(uint64, []byte)) (*Queue, error) {
	if clock == nil || arrive == nil || opt.Waiting < 1 || opt.WriteTime < 0 || opt.LinkTime < 0 || opt.WriteTime > time.Duration(math.MaxInt64)-opt.LinkTime {
		return nil, errors.New("writequeue: require a clock, arrival callback, positive capacity and nonnegative bounded delays")
	}
	return &Queue{clock: clock, target: transport.WritePeer{Addr: peer, Session: transport.NewWriteSession()}, opt: opt, arrive: arrive}, nil
}

func (q *Queue) WritePeers() []transport.WritePeer {
	if q.closed || !q.target.Session.Active() {
		return nil
	}
	return []transport.WritePeer{q.target}
}

// SendWrite freezes bytes and the exact original stream. Rejections produce no
// callback. Attempt metadata does not alter model timing or functional rights.
func (q *Queue) SendWrite(target transport.WritePeer, code uint64, payload []byte, _ transport.SendAttempt, done func(transport.WriteReceipt)) transport.SendResult {
	if done == nil || transport.CheckOutbound(code, payload) != nil || q.closed || target != q.target || !target.Session.Active() {
		return transport.NotAttached
	}
	if q.active != nil && len(q.waiting) >= q.opt.Waiting {
		return transport.QueueFull
	}
	r := &request{code: code, payload: slices.Clone(payload), done: done,
		receipt: transport.WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(payload)}}
	if q.active == nil {
		q.start(r)
	} else {
		q.waiting = append(q.waiting, r)
	}
	return transport.Queued
}

func (q *Queue) start(r *request) {
	q.active = r
	now := q.clock.Mono()
	// Work past the representable clock horizon stays pending until Close.
	if q.opt.WriteTime > time.Duration(math.MaxInt64)-now {
		return
	}
	r.timer = q.clock.At(now+q.opt.WriteTime, func() { q.complete(r) })
}

func (q *Queue) complete(r *request) {
	if q.closed || q.active != r {
		return
	}
	if !q.target.Session.Active() {
		q.Close()
		return
	}
	q.active = nil
	if q.opt.LinkTime <= time.Duration(math.MaxInt64)-q.clock.Mono() {
		q.clock.At(q.clock.Mono()+q.opt.LinkTime, func() {
			if !q.closed && q.target.Session.Active() {
				q.arrive(r.code, r.payload)
			}
		})
	}
	if len(q.waiting) != 0 {
		next := q.waiting[0]
		q.waiting[0] = nil
		q.waiting = q.waiting[1:]
		q.start(next)
	}
	r.receipt.Result = transport.LocalWriteOK
	if r.done != nil {
		r.done(r.receipt)
	}
}

// Close ends this original stream once and cancels active then queued requests
// in FIFO order. Callbacks cannot reattach or transfer outstanding work.
func (q *Queue) Close() {
	if q.closed {
		return
	}
	q.closed = true
	q.target.Session.Close()
	pending := q.waiting
	q.waiting = nil
	if q.active != nil {
		pending = append([]*request{q.active}, pending...)
		q.active = nil
	}
	for _, r := range pending {
		if r.timer != nil {
			r.timer.Stop()
		}
		r.receipt.Result = transport.LocalWriteCancelled
		if r.done != nil {
			r.done(r.receipt)
		}
	}
}
