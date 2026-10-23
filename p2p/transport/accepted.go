package transport

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// CanRecordAccepted reports support for the staged post-core receive API.
// Legacy cache observers and per-peer read-loop callbacks cannot represent a
// later core completion. They require an explicit compatible policy profile.
func (d *Dedup) CanRecordAccepted() bool {
	return d.cacheObserver == nil && d.opt.Inbound == nil
}

// RecordAccepted registers a fully accepted input for outbound suppression.
// It never invokes the legacy read-loop callback or emits a legacy cache
// operation for a later core completion. The accepted-input receiver keeps
// its independently scoped known cache rather than consulting this legacy one.
func (d *Dedup) RecordAccepted(peer types.Address, code uint64, payload []byte) bool {
	if d.completedWrites != nil || !d.CanRecordAccepted() || CheckOutbound(code, payload) != nil {
		return false
	}
	key := codec.DedupKey(payload)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.peerCache(peer).Add(key, struct{}{})
	d.known.Add(key, struct{}{})
	return true
}

// RecordAcceptedInput retains an original active stream in completion mode.
// Missing runtime ownership is unavailable, even if a matching address is now
// attached. It does not recover a session from capture metadata or WAL replay.
func (d *Dedup) RecordAcceptedInput(in Inbound) bool {
	return d.RecordAcceptedInputWithSource(in, AcceptedInputSource{})
}

func (d *Dedup) RecordAcceptedInputWithSource(in Inbound, source AcceptedInputSource) bool {
	if d.completedWrites != nil {
		return d.completedWrites.RecordAcceptedWithSource(WritePeer{Addr: in.Peer, Session: in.Stream}, in.Code, in.Payload, source)
	}
	return d.RecordAccepted(in.Peer, in.Code, in.Payload)
}
