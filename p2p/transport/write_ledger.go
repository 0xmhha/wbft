package transport

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// WriteLedgerOptions bound outstanding local requests, independently of the
// observer. These entry counts do not bound transport payloads or process heap.
type WriteLedgerOptions struct {
	Pending, PerPeer uint64
	KeyWithCode      bool
	Trace            WriteTransitionObserver
}

// WriteDecision separates a completed recent entry from pending work and from
// a local capacity refusal. Pending work is never a successful recent entry.
type WriteDecision uint8

const (
	WriteReserved WriteDecision = iota + 1
	WriteAlreadyRecent
	WriteAlreadyPending
	WritePendingFull
	WriteUnavailable
)

type writeKey struct {
	code    uint64
	payload types.Hash
}

type pendingWriteKey struct {
	target WritePeer
	key    writeKey
}

type writeReservation struct {
	owner       *WriteLedger
	target      WritePeer
	key         writeKey
	code        uint64
	payload     types.Hash
	observation uint64
	streamRun   string
}

// WriteTicket is one ledger-owned request. Its zero value owns nothing. A
// callback closes over this ticket; recorder metadata never grants ownership.
type WriteTicket struct{ reservation *writeReservation }

// WriteLedger retains recent entries only after a successful actual local
// write. Completed address-cache entries survive reconnection; outstanding
// requests from an ended stream cannot register a new entry in any stream.
// Methods never call the transport or an observer while holding the mutex.
// This type is a functional primitive, not an enabled node cache policy.
type WriteLedger struct {
	mu                         sync.Mutex
	observation, traceSequence uint64
	traceOwner                 *AttemptOwner
	traceRun                   string
	traceExhausted             bool
	opt                        WriteLedgerOptions
	closed                     bool
	pending                    map[pendingWriteKey]*writeReservation
	counts                     map[types.Address]uint64
	recent                     *lru[types.Address, *lru[writeKey, struct{}]]
}

// NewWriteLedger requires explicit positive pending entry limits. It uses the
// existing address/recent capacities; it does not select an operating budget.
func NewWriteLedger(opt WriteLedgerOptions) (*WriteLedger, error) {
	if opt.Pending == 0 || opt.PerPeer == 0 || opt.PerPeer > opt.Pending {
		return nil, errors.New("transport: write ledger requires positive pending and per-peer limits")
	}
	l := &WriteLedger{opt: opt, pending: make(map[pendingWriteKey]*writeReservation), counts: make(map[types.Address]uint64), recent: newLRU[types.Address, *lru[writeKey, struct{}]](InmemoryPeers)}
	if opt.Trace != nil {
		l.observation = nextObservationID()
		if source, ok := opt.Trace.(interface {
			AttemptOwner() *AttemptOwner
			CaptureRun() string
		}); ok {
			l.traceOwner, l.traceRun = source.AttemptOwner(), source.CaptureRun()
		}
		l.mu.Lock()
		event := l.transition(WriteStart)
		event.PendingLimit, event.PerPeerLimit, event.KeyWithCode = opt.Pending, opt.PerPeer, opt.KeyWithCode
		l.observedUnlock(&event)
	}
	return l, nil
}

func (l *WriteLedger) key(code uint64, payload []byte) writeKey {
	key := writeKey{payload: codec.DedupKey(payload)}
	if l.opt.KeyWithCode {
		key.code = code
	}
	return key
}

func (l *WriteLedger) release(r *writeReservation) {
	delete(l.pending, pendingWriteKey{target: r.target, key: r.key})
	if l.counts[r.target.Addr] <= 1 {
		delete(l.counts, r.target.Addr)
	} else {
		l.counts[r.target.Addr]--
	}
}

func (l *WriteLedger) pruneClosed(t *WriteTransition) {
	for _, r := range l.pending { //wbft:unordered closed-stream releases commute; observation IDs are sorted before publication
		if !r.target.Session.Active() {
			if l.opt.Trace != nil {
				t.Pruned = append(t.Pruned, r.observation)
			}
			l.release(r)
		}
	}
}

// Prepare reserves functional ownership before calling SendWrite. Callers must
// distinguish the decision when no ticket is returned; capacity refusal and
// pending suppression are not evidence that a message was written.
func (l *WriteLedger) Prepare(target WritePeer, code uint64, payload []byte) (ticket WriteTicket, decision WriteDecision) {
	return l.prepare(target, code, payload, nil)
}

func (l *WriteLedger) prepare(target WritePeer, code uint64, payload []byte, retry *RoundChangeRetrySource) (ticket WriteTicket, decision WriteDecision) {
	active := target.Session.Active()
	valid := active && CheckOutbound(code, payload) == nil
	if l.opt.Trace == nil && !valid {
		return WriteTicket{}, WriteUnavailable
	}
	key := l.key(code, payload)
	l.mu.Lock()
	event := l.transition(WritePrepare)
	if retry != nil {
		event.Retry = *retry
	}
	if l.opt.Trace != nil {
		event.Input = l.identity(target, code, key, sha256.Sum256(payload))
		event.Valid = valid
	}
	defer func() { event.Decision = decision; l.observedUnlock(&event) }()
	event.SessionActive = active && target.Session.Active()
	if l.closed || !event.SessionActive || !valid {
		return WriteTicket{}, WriteUnavailable
	}
	l.pruneClosed(&event)
	if recent, ok := l.recent.Get(target.Addr); ok {
		if _, exists := recent.Get(key); exists && retry == nil {
			return WriteTicket{}, WriteAlreadyRecent
		}
	}
	pk := pendingWriteKey{target: target, key: key}
	if l.pending[pk] != nil {
		return WriteTicket{}, WriteAlreadyPending
	}
	if uint64(len(l.pending)) >= l.opt.Pending || l.counts[target.Addr] >= l.opt.PerPeer {
		return WriteTicket{}, WritePendingFull
	}
	r := &writeReservation{owner: l, target: target, key: key, code: code, payload: sha256.Sum256(payload), observation: event.Sequence}
	if l.opt.Trace != nil {
		r.streamRun = event.Input.SessionRun
	}
	l.pending[pk] = r
	l.counts[target.Addr]++
	event.Request = r.observation
	return WriteTicket{reservation: r}, WriteReserved
}

func (l *WriteLedger) owns(ticket WriteTicket) *writeReservation {
	r := ticket.reservation
	if r == nil || r.owner != l || l.pending[pendingWriteKey{target: r.target, key: r.key}] != r {
		return nil
	}
	return r
}

// QueueResult reclaims a rejected queue request. A Queued return never revives
// ownership that a synchronous completion or stream close already consumed.
func (l *WriteLedger) QueueResult(ticket WriteTicket, result SendResult) {
	if result == Queued && l.opt.Trace == nil {
		return
	}
	l.mu.Lock()
	event := l.transition(WriteQueueResult)
	l.ticketIdentity(&event, ticket)
	event.Queue = result
	defer l.observedUnlock(&event)
	if r := l.owns(ticket); r != nil {
		event.Owned = true
		if result != Queued {
			l.release(r)
			event.Released = true
		}
	}
}

// Complete accepts only the exact ticket, stream, code and queued bytes. It
// returns true only when this completion adds a successful recent entry.
func (l *WriteLedger) Complete(ticket WriteTicket, receipt WriteReceipt) bool {
	l.mu.Lock()
	event := l.transition(WriteComplete)
	l.ticketIdentity(&event, ticket)
	if l.opt.Trace != nil {
		event.Receipt = WriteIdentity{Peer: receipt.Target.Addr, Session: receipt.Target.Session.ObservationID(), SessionRun: receipt.Target.Session.ObservationRun(), Code: receipt.Code, PayloadSHA256: receipt.PayloadSHA256}
		event.Result = receipt.Result
	}
	defer l.observedUnlock(&event)
	r := l.owns(ticket)
	event.Owned = r != nil
	if r == nil || receipt.Target != r.target || receipt.Code != r.code || receipt.PayloadSHA256 != r.payload {
		return false
	}
	event.Matched = true
	if receipt.Result != LocalWriteOK && receipt.Result != LocalWriteCancelled && receipt.Result != LocalWriteError {
		return false
	}
	event.Valid = true
	l.release(r)
	event.Released = true
	event.SessionActive = r.target.Session.Active()
	if l.closed || receipt.Result != LocalWriteOK || !event.SessionActive {
		return false
	}
	m, ok := l.recent.Get(r.target.Addr)
	if !ok {
		m = newLRU[writeKey, struct{}](InmemoryMessages)
		l.recent.Add(r.target.Addr, m)
	}
	m.Add(r.key, struct{}{})
	event.Registered = true
	return true
}

// RecordAccepted records a fully accepted reception on its original active
// stream. An unavailable or closed stream never falls back to a current peer
// address lookup. This shares the recent LRU with successful local writes.
func (l *WriteLedger) RecordAccepted(target WritePeer, code uint64, payload []byte) bool {
	return l.RecordAcceptedWithSource(target, code, payload, AcceptedInputSource{})
}

func (l *WriteLedger) RecordAcceptedWithSource(target WritePeer, code uint64, payload []byte, source AcceptedInputSource) bool {
	valid := CheckOutbound(code, payload) == nil
	if l.opt.Trace == nil && !valid {
		return false
	}
	key := l.key(code, payload)
	l.mu.Lock()
	event := l.transition(WriteAccept)
	if l.opt.Trace != nil {
		event.AcceptedSource = source
	}
	if l.opt.Trace != nil {
		event.Input = l.identity(target, code, key, sha256.Sum256(payload))
	}
	event.Valid = valid
	event.SessionActive = target.Session.Active()
	defer l.observedUnlock(&event)
	if !valid || l.closed || !event.SessionActive {
		return false
	}
	m, ok := l.recent.Get(target.Addr)
	if !ok {
		m = newLRU[writeKey, struct{}](InmemoryMessages)
		l.recent.Add(target.Addr, m)
	}
	m.Add(key, struct{}{})
	event.Registered = true
	return true
}

// Recent inspects completed entries without changing their LRU order.
func (l *WriteLedger) Recent(peer types.Address, code uint64, payload []byte) bool {
	key := l.key(code, payload)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.recent.items[peer]
	return ok && entry.Value.(*lruEntry[types.Address, *lru[writeKey, struct{}]]).val.Contains(key)
}

// Pending counts owned outstanding requests after reclaiming ended streams.
// It accounts for ledger records, not payload bytes still owned by an adapter.
func (l *WriteLedger) Pending() uint64 {
	l.mu.Lock()
	event := l.transition(WritePrune)
	defer l.observedUnlock(&event)
	l.pruneClosed(&event)
	return uint64(len(l.pending))
}

// Close ends this ledger lifetime without closing transport-owned sessions.
// Old callbacks can never transfer ownership into a replacement ledger.
func (l *WriteLedger) Close() {
	l.mu.Lock()
	event := l.transition(WriteClose)
	defer l.observedUnlock(&event)
	l.closed = true
	clear(l.pending)
	clear(l.counts)
	l.recent = newLRU[types.Address, *lru[writeKey, struct{}]](InmemoryPeers)
}

func (l *WriteLedger) Closed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}
