package runner

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
)

type receiveContext struct {
	snapshot *consensus.Snapshot
	scope    *transport.ValidationScope
}

func sameReceiveContext(a, b *consensus.Snapshot) bool {
	return a != nil && b != nil && a.Running == b.Running && a.View.Cmp(b.View) == 0 && a.State == b.State && a.PriorRound.Cmp(b.PriorRound) == 0 && a.Validators == b.Validators && a.PriorValidators == b.PriorValidators
}

// updateReceiveContext runs on the consensus goroutine. Other goroutines only
// load the immutable published context; they never authenticate into it.
func (r *Runner) updateReceiveContext(snap *consensus.Snapshot) *receiveContext {
	if r.receiveCache == nil {
		return nil
	}
	old := r.receiveContext.Load()
	if old != nil && sameReceiveContext(old.snapshot, snap) {
		return old
	}
	if old != nil {
		old.scope.Close()
	}
	if snap == nil || !snap.Running {
		r.receiveContext.Store(nil)
		return nil
	}
	next := &receiveContext{snapshot: snap, scope: r.newReceiveScope(snap)}
	r.receiveContext.Store(next)
	return next
}

func (r *Runner) receiveAlreadyKnown(in transport.Inbound) bool {
	current := r.receiveContext.Load()
	return current != nil && r.receiveCache.Known(current.scope, in.Code, in.Payload)
}

// beginReceiveCheck is deliberately at core dispatch, not in the read loop or
// receive worker. Even an input checked against an earlier snapshot must pass
// the core's full current validation before it may become known.
func (r *Runner) beginReceiveCheck(q queued) (transport.ReceiveTicket, transport.Inbound, bool) {
	if r.receiveCache == nil {
		return transport.ReceiveTicket{}, transport.Inbound{}, false
	}
	m, ok := q.in.(consensus.Message)
	if !ok {
		return transport.ReceiveTicket{}, transport.Inbound{}, false
	}
	current := r.updateReceiveContext(r.core.Snapshot())
	if current == nil {
		return transport.ReceiveTicket{}, transport.Inbound{}, false
	}
	in := transport.Inbound{Peer: m.Peer, Code: uint64(m.Code), Payload: m.Payload, RecvMono: m.RecvMono, Capture: q.capture, Stream: q.stream, Origin: q.origin}
	origin := q.origin
	if q.deferred != nil {
		origin = transport.ReceiveOrigin{WriterRun: q.deferred.record.CaptureRun, CaptureID: q.deferred.record.Capture}
		in.Capture = origin.CaptureID
		in.Stream = q.deferred.record.stream
	}
	ticket, decision := r.receiveCache.Prepare(current.scope, in, origin)
	if decision == transport.ReceiveKnown && q.via == viaPeer && q.deferred == nil {
		r.prefilter(in, nil, event.DropSilent, "duplicate", false)
		return transport.ReceiveTicket{}, in, true
	}
	// A local bookkeeping limit never discards an already admitted own or
	// deferred consensus input. Such an input can run without caching.
	return ticket, in, false
}

// completeReceiveCheck registers only the core's successful direct ACCEPT.
// A signature check, queue admission, backlog entry, deferred proposal, or
// ignored input alone is insufficient. Matching the original input prevents
// an incidental backlog outcome in the same step from becoming its proof.
func (r *Runner) completeReceiveCheck(ticket transport.ReceiveTicket, in transport.Inbound, outs []consensus.Output) {
	if r.receiveCache == nil || ticket == (transport.ReceiveTicket{}) {
		return
	}
	key := codec.DedupKey(in.Payload)
	for index, out := range outs {
		o, ok := out.(consensus.Outcome)
		if ok && o.Relayed && (o.Via == "direct" || o.Via == "self") && uint64(o.Code) == in.Code && o.Peer == in.Peer && o.DedupKey == key {
			source := transport.ReceiveAcceptSource{EngineRun: r.engineRun, Step: r.step, Output: uint64(index + 1), Via: o.Via}
			if r.receiveCache.AcceptWithSource(ticket, in, source) == transport.ReceiveRegistered && r.d.ReceiveCacheRecorded != nil {
				r.d.ReceiveCacheRecorded(in.Code)
			}
			if r.d.Transport != nil && in.Peer != r.cfg.Core.Self {
				r.d.Transport.RecordAcceptedInputWithSource(in, ticket.AcceptedSource(source))
			}
			return
		}
	}
	// The deferred Cancel in handle also reclaims errors before core dispatch.
}
