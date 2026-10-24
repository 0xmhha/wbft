package journal

import (
	"fmt"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
	"math"
)

const ReceiveDispatchSourceVersion uint64 = 1

// ReceiveDispatchRec retains the original checking-ledger Prepare call through
// actual core dispatch or a ticketless known discard. It is a separate v1
// diagnostic record, not a functional replay input or physical I/O proof.
type ReceiveDispatchRec struct {
	Version, Sequence, Request               uint64
	EngineRun, BeforeStep, Step              uint64
	Action, Via                              string
	Source                                   transport.ReceivePreparationSource
	Scope, Decision                          uint64
	ContextHash                              types.Hash
	Selection, InboxRequest, InternalRequest uint64
	Capture                                  uint64
	Origin                                   transport.ReceiveOrigin
	StreamRun                                string
	Stream                                   uint64
	InputKind                                string
	Input                                    []byte
	Mono, WallNs                             uint64
	Unavailable                              string
}
type receiveDispatchRLP struct {
	Format, JSeq uint64
	Source       ReceiveDispatchRec
}

func validReceiveDispatchRec(r *ReceiveDispatchRec) bool {
	if r.Version != ReceiveDispatchSourceVersion || r.EngineRun == 0 || r.BeforeStep == 0 || r.Mono > math.MaxInt64 || r.InputKind != inputlog.KindMessage {
		return false
	}
	switch r.Unavailable {
	case "", "metadata_exhausted", "input_encoding", "snapshot_encoding", "unqualified_ledger", "preparation_source_missing", "scope_unavailable", "selection_source_missing", "inbox_source_missing", "internal_source_missing", "deferred_input", "replayed_prefix":
	default:
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	if r.Decision < uint64(transport.ReceiveReserved) || r.Decision > uint64(transport.ReceiveUnavailable) {
		return false
	}
	switch r.Via {
	case "peer", "internal":
	default:
		return false
	}
	switch r.Action {
	case "prepare":
		if r.Request != r.Sequence || r.Step != 0 {
			return false
		}
	case "dispatch":
		if r.Step == 0 || r.BeforeStep == math.MaxUint64 || r.Step != r.BeforeStep+1 {
			return false
		}
	case "discard":
		if r.Step != 0 || r.Via != "peer" || r.Decision != uint64(transport.ReceiveKnown) {
			return false
		}
	default:
		return false
	}
	return r.Unavailable != "" || r.Request > 0 && r.Source.WriterRun != "" && r.Source.Ledger > 0 && r.Source.Sequence > 0 && r.Scope > 0 && r.Selection > 0 && len(r.Input) > 0
}
func encodeReceiveDispatchRec(r *ReceiveDispatchRec, jseq uint64) ([]byte, error) {
	if !validReceiveDispatchRec(r) {
		return nil, fmt.Errorf("journal: invalid receive dispatch source")
	}
	return rlp.Encode(&receiveDispatchRLP{Format: Format, JSeq: jseq, Source: *r})
}
func decodeReceiveDispatchRec(body []byte) (Record, error) {
	var w receiveDispatchRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: receive dispatch source: %v", ErrRecord, err)
	}
	if w.Format != Format || !validReceiveDispatchRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid receive dispatch source", ErrRecord)
	}
	return Record{Kind: KindReceiveDispatch, JSeq: w.JSeq, Body: &w.Source}, nil
}
