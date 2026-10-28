package journal

import (
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

const ReceiveFailureRecordVersion uint64 = 1

// ReceiveFailureCacheRec records a cache operation, never a verifier call.
// Syntax and bookkeeping coordinates alone do not authenticate the failure.
type ReceiveFailureCacheRec struct {
	Version    uint64
	Transition transport.ReceiveFailureEvent
	Mono       time.Duration
	WallNs     int64
}

type receiveFailureRLP struct {
	Format, JSeq, Version                 uint64
	Run                                   string
	Cache, Sequence, Context              uint64
	RequestedRun                          string
	RequestedCache, RequestedContext      uint64
	Action                                string
	Source, Original                      transport.ReceiveFailureSource
	Reference                             transport.ReceiveFailureRef
	Code                                  uint64
	Payload                               types.Hash
	Class, Before, After, Capacity, Flags uint64
	Unavailable                           string
	Mono, WallNs                          uint64
}

func qualifiedFailureRef(ref transport.ReceiveFailureRef) bool {
	return ref.Run != "" && ref.Cache != 0 && ref.Sequence != 0
}

func knownFailureSource(s transport.ReceiveFailureSource, worker bool) bool {
	return s.EngineRun != 0 && s.SnapshotHash != (types.Hash{}) && s.SnapshotPhase >= transport.ReceiveFailureStart && s.SnapshotPhase <= transport.ReceiveFailureReplay && (!worker || s.WorkerRequest != 0)
}

func failureClassKnown(class transport.ReceiveFailureClass) bool {
	return class == transport.ReceiveSignatureFailure || class == transport.ReceiveMembershipFailure
}

func validReceiveFailureEvent(e transport.ReceiveFailureEvent) bool {
	if e.Capacity == 0 || e.Capacity > transport.InmemoryMessages || e.Before > e.Capacity || e.After > e.Capacity {
		return false
	}
	switch e.Unavailable {
	case "", "metadata_exhausted", "namespace_unavailable", "snapshot_source_unavailable", "worker_source_unavailable", "conflicting_failure":
	default:
		return false
	}
	if e.Sequence == 0 && e.Unavailable != "metadata_exhausted" {
		return false
	}
	if e.Unavailable == "" && (e.Run == "" || e.Cache == 0 || e.Sequence == 0) {
		return false
	}
	if e.Active && (e.Context == 0 && e.Unavailable == "" || e.Closed) || e.Hit && (!e.Active || e.Action != "lookup") || e.Stored && (!e.Active || e.Action != "record") {
		return false
	}
	zeroRef, zeroSource := transport.ReceiveFailureRef{}, transport.ReceiveFailureSource{}
	if e.Action == "lookup" || e.Action == "record" {
		if e.Payload == (types.Hash{}) || e.Unavailable == "" && !knownFailureSource(e.Source, true) {
			return false
		}
		if e.Active && (e.RequestedCache != e.Cache || e.RequestedContext != e.Context || e.RequestedRun != e.Run) {
			return false
		}
	} else if e.Code != 0 || e.Payload != (types.Hash{}) || e.Class != 0 || e.Reference != zeroRef || e.Original != zeroSource || e.RequestedCache != 0 || e.RequestedContext != 0 || e.RequestedRun != "" {
		return false
	}
	switch e.Action {
	case "context":
		return !e.Hit && !e.Stored && e.After == 0 && (!e.Active || e.Context == e.Sequence) && (e.Unavailable != "" || knownFailureSource(e.Source, false))
	case "lookup":
		if e.Stored || e.Before != e.After {
			return false
		}
		if !e.Hit {
			return e.Class == 0 && e.Reference == zeroRef && e.Original == zeroSource
		}
		return failureClassKnown(e.Class) && (e.Unavailable != "" || qualifiedFailureRef(e.Reference) && e.Reference.Run == e.Run && e.Reference.Cache == e.Cache && e.Reference.Sequence < e.Sequence && knownFailureSource(e.Original, true))
	case "record":
		if e.Hit {
			return false
		}
		if e.Stored {
			after := e.Before + 1
			if after > e.Capacity {
				after = e.Capacity
			}
			return failureClassKnown(e.Class) && e.Code >= transport.CodeFirst && e.Code <= transport.CodeLast && e.After == after && e.Original == zeroSource && (e.Unavailable != "" || e.Reference == (transport.ReceiveFailureRef{Run: e.Run, Cache: e.Cache, Sequence: e.Sequence}))
		}
		if e.After != e.Before {
			return false
		}
		if e.Reference == zeroRef {
			return e.Original == zeroSource
		}
		return failureClassKnown(e.Class) && (e.Unavailable != "" || qualifiedFailureRef(e.Reference) && e.Reference.Run == e.Run && e.Reference.Cache == e.Cache && e.Reference.Sequence < e.Sequence && knownFailureSource(e.Original, true))
	case "invalidate":
		return !e.Active && !e.Hit && !e.Stored && e.After == 0 && e.Source == zeroSource
	case "close":
		return e.Closed && !e.Active && !e.Hit && !e.Stored && e.After == 0 && e.Source == zeroSource
	default:
		return false
	}
}

func encodeReceiveFailureRec(r *ReceiveFailureCacheRec, jseq uint64) ([]byte, error) {
	e := r.Transition
	if r.Version != ReceiveFailureRecordVersion || r.Mono < 0 || r.WallNs < 0 || !validReceiveFailureEvent(e) {
		return nil, fmt.Errorf("journal: invalid receive failure cache observation")
	}
	var flags uint64
	for bit, value := range []bool{e.Active, e.Hit, e.Stored, e.Closed} {
		if value {
			flags |= 1 << bit
		}
	}
	return rlp.Encode(&receiveFailureRLP{Format: Format, JSeq: jseq, Version: r.Version, Run: e.Run, Cache: e.Cache, Sequence: e.Sequence, Context: e.Context, RequestedRun: e.RequestedRun, RequestedCache: e.RequestedCache, RequestedContext: e.RequestedContext, Action: e.Action, Source: e.Source, Original: e.Original, Reference: e.Reference, Code: e.Code, Payload: e.Payload, Class: uint64(e.Class), Before: e.Before, After: e.After, Capacity: e.Capacity, Flags: flags, Unavailable: e.Unavailable, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}

func decodeReceiveFailureRec(body []byte) (Record, error) {
	var w receiveFailureRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: receive failure cache: %v", ErrRecord, err)
	}
	if w.Format != Format || w.Version != ReceiveFailureRecordVersion || w.Flags > 15 || w.Class > 255 || w.Mono > math.MaxInt64 || w.WallNs > math.MaxInt64 {
		return Record{}, fmt.Errorf("%w: receive failure cache encoding", ErrRecord)
	}
	e := transport.ReceiveFailureEvent{Run: w.Run, Cache: w.Cache, Sequence: w.Sequence, Context: w.Context, RequestedRun: w.RequestedRun, RequestedCache: w.RequestedCache, RequestedContext: w.RequestedContext, Action: w.Action, Source: w.Source, Original: w.Original, Reference: w.Reference, Code: w.Code, Payload: w.Payload, Class: transport.ReceiveFailureClass(w.Class), Before: w.Before, After: w.After, Capacity: w.Capacity, Active: w.Flags&1 != 0, Hit: w.Flags&2 != 0, Stored: w.Flags&4 != 0, Closed: w.Flags&8 != 0, Unavailable: w.Unavailable}
	if !validReceiveFailureEvent(e) {
		return Record{}, fmt.Errorf("%w: receive failure cache observation", ErrRecord)
	}
	return Record{Kind: KindReceiveFailure, JSeq: w.JSeq, Body: &ReceiveFailureCacheRec{Version: w.Version, Transition: e, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}}, nil
}
