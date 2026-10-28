package journal

import (
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/p2p/transport"
)

// InboxFailureHitRec consumes one original inbox request using a prior failed
// check. It is a separate record kind, never a newly executed InboxRec check.
type InboxFailureHitRec struct {
	Version          uint64
	Source           InboxRec
	Lookup, Original transport.ReceiveFailureRef
	Class            transport.ReceiveFailureClass
	Unavailable      string
}

type inboxFailureRLP struct {
	Format, JSeq uint64
	Source       InboxFailureHitRec
}

func validInboxFailureHit(r *InboxFailureHitRec) bool {
	if r.Version != ReceiveFailureRecordVersion || r.Source.Action != "failure_hit" || r.Source.WallNs > math.MaxInt64 || !failureClassKnown(r.Class) {
		return false
	}
	if r.Class == transport.ReceiveSignatureFailure && r.Source.Result != "signature" || r.Class == transport.ReceiveMembershipFailure && r.Source.Result != "membership" {
		return false
	}
	switch r.Unavailable {
	case "", "failure_reference_unavailable":
	default:
		return false
	}
	// Reuse only the old field-shape checks on a detached local copy. Neither
	// encoder nor decoder emits this copy as the old Inbox/check record kind.
	shape := r.Source
	shape.Action = "check"
	if !validInboxRec(&shape) {
		return false
	}
	if r.Unavailable == "" && (!qualifiedFailureRef(r.Lookup) || !qualifiedFailureRef(r.Original) || r.Lookup.Run != r.Original.Run || r.Lookup.Cache != r.Original.Cache || r.Original.Sequence >= r.Lookup.Sequence) {
		return false
	}
	return true
}

func encodeInboxFailureHit(r *InboxFailureHitRec, jseq uint64) ([]byte, error) {
	if !validInboxFailureHit(r) {
		return nil, fmt.Errorf("journal: invalid inbox failure hit")
	}
	return rlp.Encode(&inboxFailureRLP{Format: Format, JSeq: jseq, Source: *r})
}

func decodeInboxFailureHit(body []byte) (Record, error) {
	var w inboxFailureRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: inbox failure hit: %v", ErrRecord, err)
	}
	if w.Format != Format || !validInboxFailureHit(&w.Source) {
		return Record{}, fmt.Errorf("%w: inbox failure hit", ErrRecord)
	}
	return Record{Kind: KindInboxFailureHit, JSeq: w.JSeq, Body: &w.Source}, nil
}
