package transport

import "errors"

const CachePolicyProfile = "accepted_completed_v1"

// CachePolicyLimits enables accepted-input and completed-write caching with
// code-aware keys. All four limits count pending records, not process heap,
// raw payload bytes, I/O time or remote delivery. Nil node settings stay off.
type CachePolicyLimits struct {
	ReceivePending uint64 `json:"receive_pending,string"`
	ReceivePerPeer uint64 `json:"receive_per_peer,string"`
	WritePending   uint64 `json:"write_pending,string"`
	WritePerPeer   uint64 `json:"write_per_peer,string"`
}

func (l CachePolicyLimits) Validate() error {
	if l.ReceivePending == 0 || l.ReceivePerPeer == 0 || l.ReceivePerPeer > l.ReceivePending || l.WritePending == 0 || l.WritePerPeer == 0 || l.WritePerPeer > l.WritePending {
		return errors.New("transport: cache policy requires four positive pending limits with per-peer limits within totals")
	}
	return nil
}

func (l CachePolicyLimits) ReceiveOptions() ReceiveLedgerOptions {
	return ReceiveLedgerOptions{Pending: l.ReceivePending, PerPeer: l.ReceivePerPeer, KeyWithCode: true}
}

func (l CachePolicyLimits) WriteOptions() WriteLedgerOptions {
	return WriteLedgerOptions{Pending: l.WritePending, PerPeer: l.WritePerPeer, KeyWithCode: true}
}
