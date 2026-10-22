package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/p2p/transport"
)

// WriteCacheRec observes the accepted/completed policy's actual write ledger.
// Its process-local ledger/session numbers are qualified by the segment run.
// This is distinct from CacheRec; it neither enables runtime replay nor proves
// physical delivery or a core ACCEPT without the corresponding source records.
type WriteCacheRec struct {
	Transition transport.WriteTransition
	Mono       time.Duration
	WallNs     int64
}

type writeCacheRLP struct {
	Format, JSeq                      uint64
	Ledger, Sequence, Action, Request uint64
	Input, Receipt                    transport.WriteIdentity
	Decision, Queue, Result, Flags    uint64
	PendingBefore, PendingAfter       uint64
	Pruned                            []uint64
	PendingLimit, PerPeerLimit        uint64
	Mono, WallNs                      uint64
}

func validWriteTransition(t transport.WriteTransition) bool {
	if t.Ledger == 0 || t.Sequence == 0 || t.Action < transport.WriteStart || t.Action > transport.WriteClose {
		return false
	}
	zero := transport.WriteIdentity{}
	if t.Action != transport.WriteStart && (t.Sequence == 1 || t.PendingLimit != 0 || t.PerPeerLimit != 0 || t.KeyWithCode) {
		return false
	}
	if t.Action != transport.WritePrepare && t.Decision != 0 {
		return false
	}
	if t.Action != transport.WriteQueueResult && t.Queue != 0 {
		return false
	}
	if t.Action != transport.WriteComplete && (t.Result != 0 || t.Receipt != zero || t.Matched) {
		return false
	}
	if t.Action != transport.WritePrepare && t.Action != transport.WritePrune && len(t.Pruned) != 0 {
		return false
	}
	if t.Action != transport.WriteQueueResult && t.Action != transport.WriteComplete && (t.Owned || t.Released) {
		return false
	}
	if t.Action != transport.WriteComplete && t.Action != transport.WriteAccept && t.Registered {
		return false
	}
	if t.Action != transport.WritePrepare && t.Action != transport.WriteComplete && t.Action != transport.WriteAccept && t.Valid {
		return false
	}
	if t.Action != transport.WritePrepare && t.Action != transport.WriteComplete && t.Action != transport.WriteQueueResult && t.Action != transport.WriteAccept && t.SessionActive {
		return false
	}
	if t.Action != transport.WritePrepare && t.Action != transport.WriteComplete && t.Action != transport.WriteQueueResult && t.Action != transport.WriteAccept && t.Input != zero {
		return false
	}
	if t.Action != transport.WritePrepare && t.Action != transport.WriteComplete && t.Action != transport.WriteQueueResult && t.Request != 0 {
		return false
	}
	pruned := uint64(len(t.Pruned))
	if pruned > t.PendingBefore {
		return false
	}
	seen := make(map[uint64]bool, len(t.Pruned))
	for _, id := range t.Pruned {
		if id == 0 || id >= t.Sequence || seen[id] {
			return false
		}
		seen[id] = true
	}
	afterPrune := t.PendingBefore - pruned
	switch t.Action {
	case transport.WriteStart:
		return t.Sequence == 1 && t.PendingLimit > 0 && t.PerPeerLimit > 0 && t.PerPeerLimit <= t.PendingLimit && t.PendingBefore == 0 && t.PendingAfter == 0 && !t.Closed
	case transport.WritePrepare:
		if t.Input.Key == ([32]byte{}) || t.Input.PayloadSHA256 == ([32]byte{}) {
			return false
		}
		available := t.Valid && t.SessionActive && !t.Closed
		if !available {
			return t.Decision == transport.WriteUnavailable && t.Request == 0 && pruned == 0 && t.PendingAfter == t.PendingBefore
		}
		if t.Input.Session == 0 {
			return false
		}
		if t.Decision == transport.WriteReserved {
			return t.Request == t.Sequence && afterPrune != ^uint64(0) && t.PendingAfter == afterPrune+1
		}
		return t.Request == 0 && t.PendingAfter == afterPrune && (t.Decision == transport.WriteAlreadyRecent || t.Decision == transport.WriteAlreadyPending || t.Decision == transport.WritePendingFull)
	case transport.WriteQueueResult, transport.WriteComplete:
		if t.Request == 0 {
			if t.Input != zero || t.Owned || t.SessionActive {
				return false
			}
		} else if t.Request >= t.Sequence || t.Input.Session == 0 || t.Input.Key == ([32]byte{}) || t.Input.PayloadSHA256 == ([32]byte{}) {
			return false
		}
		if t.Action == transport.WriteQueueResult {
			if t.Queue > transport.QueueFull || t.Released != (t.Owned && t.Queue != transport.Queued) {
				return false
			}
		} else {
			if t.Result < transport.LocalWriteOK || t.Result > transport.LocalWriteError || t.Receipt.Key != ([32]byte{}) {
				return false
			}
			matches := t.Owned && t.Input.Peer == t.Receipt.Peer && t.Input.Session == t.Receipt.Session && t.Input.Code == t.Receipt.Code && t.Input.PayloadSHA256 == t.Receipt.PayloadSHA256
			if t.Matched != matches || t.Valid != matches || t.Released != matches || t.Registered != (matches && t.Result == transport.LocalWriteOK && t.SessionActive && !t.Closed) {
				return false
			}
		}
		if t.Released {
			return t.PendingBefore > 0 && t.PendingAfter == t.PendingBefore-1
		}
		return t.PendingAfter == t.PendingBefore
	case transport.WriteAccept:
		return t.Request == 0 && t.Input.Key != ([32]byte{}) && t.Input.PayloadSHA256 != ([32]byte{}) && (!t.SessionActive || t.Input.Session != 0) && t.Registered == (t.Valid && t.SessionActive && !t.Closed) && t.PendingAfter == t.PendingBefore
	case transport.WritePrune:
		return t.PendingAfter == afterPrune
	case transport.WriteClose:
		return t.Closed && t.PendingAfter == 0
	}
	return false
}

func writeFlags(t transport.WriteTransition) uint64 {
	var flags uint64
	for i, v := range []bool{t.Owned, t.Matched, t.Valid, t.Released, t.Registered, t.SessionActive, t.Closed, t.KeyWithCode} {
		if v {
			flags |= 1 << i
		}
	}
	return flags
}

func encodeWriteCacheRec(r *WriteCacheRec, jseq uint64) ([]byte, error) {
	t := r.Transition
	if r.Mono < 0 || !validWriteTransition(t) {
		return nil, fmt.Errorf("journal: invalid completed-write cache observation")
	}
	return rlp.Encode(&writeCacheRLP{Format: Format, JSeq: jseq, Ledger: t.Ledger, Sequence: t.Sequence, Action: uint64(t.Action), Request: t.Request, Input: t.Input, Receipt: t.Receipt, Decision: uint64(t.Decision), Queue: uint64(t.Queue), Result: uint64(t.Result), Flags: writeFlags(t), PendingBefore: t.PendingBefore, PendingAfter: t.PendingAfter, Pruned: t.Pruned, PendingLimit: t.PendingLimit, PerPeerLimit: t.PerPeerLimit, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}

func decodeWriteCacheRec(body []byte) (Record, error) {
	var w writeCacheRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: completed-write cache: %v", ErrRecord, err)
	}
	if w.Format != Format || w.Action > 255 || w.Decision > 255 || w.Queue > 255 || w.Result > 255 || w.Flags > 255 {
		return Record{}, fmt.Errorf("%w: invalid completed-write cache encoding", ErrRecord)
	}
	t := transport.WriteTransition{Ledger: w.Ledger, Sequence: w.Sequence, Action: transport.WriteAction(w.Action), Request: w.Request, Input: w.Input, Receipt: w.Receipt, Decision: transport.WriteDecision(w.Decision), Queue: transport.SendResult(w.Queue), Result: transport.LocalWriteResult(w.Result), Owned: w.Flags&1 != 0, Matched: w.Flags&2 != 0, Valid: w.Flags&4 != 0, Released: w.Flags&8 != 0, Registered: w.Flags&16 != 0, SessionActive: w.Flags&32 != 0, Closed: w.Flags&64 != 0, KeyWithCode: w.Flags&128 != 0, PendingBefore: w.PendingBefore, PendingAfter: w.PendingAfter, Pruned: w.Pruned, PendingLimit: w.PendingLimit, PerPeerLimit: w.PerPeerLimit}
	r := &WriteCacheRec{Transition: t, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}
	if r.Mono < 0 || !validWriteTransition(t) {
		return Record{}, fmt.Errorf("%w: invalid completed-write cache observation", ErrRecord)
	}
	return Record{Kind: KindWriteCache, JSeq: w.JSeq, Body: r}, nil
}
