package transport

import (
	"bytes"
	"slices"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// CompletedWritesEnabled also marks legacy payload-only cache queries as
// unavailable. The owning runner must supply the accepted-input receiver.
func (d *Dedup) CompletedWritesEnabled() bool { return d.completedWrites != nil }

// CompletedWritesClosed reports an ended cache lifetime. A new receiver must
// use a new Dedup rather than transfer outstanding ownership across runners.
func (d *Dedup) CompletedWritesClosed() bool {
	return d.completedWrites != nil && d.completedWrites.Closed()
}

// CloseCompletedWrites retires only functional cache ownership. The adapter
// still owns its streams and I/O, and callbacks cannot revive this ledger.
func (d *Dedup) CloseCompletedWrites() {
	if d.completedWrites != nil {
		d.completedWrites.Close()
	}
}

// SentOrReceivedCode inspects recent entries in their actual key domain.
func (d *Dedup) SentOrReceivedCode(peer types.Address, code uint64, payload []byte) bool {
	if d.completedWrites != nil {
		return d.completedWrites.Recent(peer, code, payload)
	}
	return d.SentOrReceived(peer, payload)
}

func (d *Dedup) gossipCompleted(vs *validator.Set, code uint64, payload []byte, cause event.SendCause) GossipTargets {
	plan := GossipTargets{Available: vs != nil}
	if vs == nil || CheckOutbound(code, payload) != nil {
		return plan
	}
	// The session is frozen with each target; no callback may look up a new
	// stream by address. No cache lock is held over SendWrite or its callback.
	var candidates []WritePeer
	for _, target := range d.writeSender.WritePeers() {
		if target.Addr == d.opt.Self || !vs.Contains(target.Addr) || !target.Session.Active() {
			continue
		}
		if slices.ContainsFunc(candidates, func(p WritePeer) bool { return p.Addr == target.Addr }) {
			continue
		}
		candidates = append(candidates, target)
	}
	slices.SortStableFunc(candidates, func(a, b WritePeer) int { return bytes.Compare(a.Addr[:], b.Addr[:]) })
	for _, target := range candidates {
		plan.Candidates = append(plan.Candidates, target.Addr)
		ticket, decision := d.completedWrites.Prepare(target, code, payload)
		switch decision {
		case WriteAlreadyRecent:
			plan.Suppressed = append(plan.Suppressed, target.Addr)
			if d.opt.Suppressed != nil {
				d.opt.Suppressed(cause)
			}
		case WriteAlreadyPending:
			plan.Pending = append(plan.Pending, target.Addr)
		case WriteReserved:
			plan.Targets = append(plan.Targets, target.Addr)
			result := d.writeSender.SendWrite(target, code, payload, SendAttempt{}, func(receipt WriteReceipt) {
				if d.completedWrites.Complete(ticket, receipt) && d.opt.WriteCompleted != nil {
					d.opt.WriteCompleted(code)
				}
			})
			d.completedWrites.QueueResult(ticket, result)
		case WritePendingFull:
			plan.Limited = append(plan.Limited, target.Addr)
		default:
			plan.Unavailable = append(plan.Unavailable, target.Addr)
		}
	}
	return plan
}
