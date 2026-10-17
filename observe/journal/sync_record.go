package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
)

const SyncTraceVersion uint64 = 1

// SyncRec records a submitted application sync state or its actual handling
// by the node. Request and processing sequences are separate: notifications
// may be superseded, and a wake can observe the same request more than once.
// EventBefore and EventAfter are next-event cursors around the actual control
// call, not values reconstructed from timestamps. A missing cursor or an
// exhausted sequence makes the observation incomplete. Zero request or
// operation IDs do not establish an input-to-control link.
type SyncRec struct {
	Stage                       string
	Request, Operation          uint64
	Syncing, Success            bool
	FirstBefore, FirstAfter     bool
	RunningBefore, RunningAfter bool
	Action                      string
	Failed                      bool
	EventsAvailable             bool
	EventBefore, EventAfter     uint64
	SequenceExhausted           bool
	Mono                        time.Duration
	WallNs                      int64
}

type syncRLP struct {
	Format, JSeq, Request, Operation uint64
	Stage                            string
	Syncing, Success                 uint64
	FirstBefore, FirstAfter          uint64
	RunningBefore, RunningAfter      uint64
	Action                           string
	Failed, EventsAvailable          uint64
	EventBefore, EventAfter          uint64
	SequenceExhausted                uint64
	Mono, WallNs                     uint64
}

func validSyncRec(r *SyncRec) bool {
	if r == nil || r.Mono < 0 || r.EventsAvailable && r.EventAfter < r.EventBefore {
		return false
	}
	switch r.Stage {
	case "requested":
		return r.Operation == 0 && r.Action == "" && !r.FirstBefore && !r.FirstAfter && !r.RunningBefore && !r.RunningAfter && !r.Failed && !r.EventsAvailable && r.EventBefore == 0 && r.EventAfter == 0
	case "processed":
		return r.Action == "none" || r.Action == "stop" || r.Action == "start"
	default:
		return false
	}
}

func encodeSyncRec(r *SyncRec, jseq uint64) ([]byte, error) {
	if !validSyncRec(r) {
		return nil, fmt.Errorf("journal: invalid sync control observation")
	}
	return rlp.Encode(&syncRLP{Format: Format, JSeq: jseq, Request: r.Request, Operation: r.Operation, Stage: r.Stage,
		Syncing: boolUint(r.Syncing), Success: boolUint(r.Success), FirstBefore: boolUint(r.FirstBefore), FirstAfter: boolUint(r.FirstAfter),
		RunningBefore: boolUint(r.RunningBefore), RunningAfter: boolUint(r.RunningAfter), Action: r.Action, Failed: boolUint(r.Failed),
		EventsAvailable: boolUint(r.EventsAvailable), EventBefore: r.EventBefore, EventAfter: r.EventAfter,
		SequenceExhausted: boolUint(r.SequenceExhausted), Mono: uint64(r.Mono), WallNs: uint64(r.WallNs)})
}

func decodeSyncRec(body []byte) (Record, error) {
	var w syncRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: sync: %v", ErrRecord, err)
	}
	for _, value := range []uint64{w.Syncing, w.Success, w.FirstBefore, w.FirstAfter, w.RunningBefore, w.RunningAfter, w.Failed, w.EventsAvailable, w.SequenceExhausted} {
		if value > 1 {
			return Record{}, fmt.Errorf("%w: invalid sync observation boolean", ErrRecord)
		}
	}
	r := &SyncRec{Stage: w.Stage, Request: w.Request, Operation: w.Operation, Syncing: w.Syncing == 1, Success: w.Success == 1,
		FirstBefore: w.FirstBefore == 1, FirstAfter: w.FirstAfter == 1, RunningBefore: w.RunningBefore == 1, RunningAfter: w.RunningAfter == 1,
		Action: w.Action, Failed: w.Failed == 1, EventsAvailable: w.EventsAvailable == 1, EventBefore: w.EventBefore, EventAfter: w.EventAfter,
		SequenceExhausted: w.SequenceExhausted == 1, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs)}
	if w.Format != Format || !validSyncRec(r) {
		return Record{}, fmt.Errorf("%w: invalid sync control observation", ErrRecord)
	}
	return Record{Kind: KindSync, JSeq: w.JSeq, Body: r}, nil
}
