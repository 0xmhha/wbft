package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

const AppQueueSourceVersion uint64 = 1

// AppQueueRec records the actual application-input queue mutex order. It is
// diagnostic metadata, not proof of application execution or a complete schedule.
// Request identifies the original append; engine/step bind a pop or Stop clear.
type AppQueueRec struct {
	Version, Sequence, Request uint64
	EngineRun, Step            uint64
	Action, InputKind          string
	Input                      []byte
	Before, After              uint64
	Mono                       time.Duration
	WallNs                     int64
	Unavailable                string
}

type appQueueRLP struct {
	Format, JSeq, Version, Sequence, Request uint64
	EngineRun, Step                          uint64
	Action, InputKind                        string
	Input                                    []byte
	Before, After, Mono, WallNs              uint64
	Unavailable                              string
}

func appQueueInputKind(kind string) bool {
	return kind == inputlog.KindRequest || kind == inputlog.KindNewHead || kind == inputlog.KindPeerConnected || kind == inputlog.KindCommitResult
}

func validAppQueueRec(r *AppQueueRec) bool {
	if r.Version != AppQueueSourceVersion || r.Mono < 0 {
		return false
	}
	if r.Unavailable != "" && r.Unavailable != "metadata_exhausted" && r.Unavailable != "input_encoding" {
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	if r.Action == "clear" {
		return r.Request == 0 && r.EngineRun > 0 && r.Step > 0 && r.After == 0 && r.InputKind == "" && len(r.Input) == 0
	}
	if !appQueueInputKind(r.InputKind) || r.Unavailable == "" && (r.Request == 0 || len(r.Input) == 0) {
		return false
	}
	switch r.Action {
	case "append":
		return r.EngineRun == 0 && r.Step == 0 && r.Request == r.Sequence && r.Before != ^uint64(0) && r.After == r.Before+1
	case "coalesce":
		return r.EngineRun == 0 && r.Step == 0 && r.InputKind == inputlog.KindNewHead && r.Before > 0 && r.Before == r.After
	case "pop":
		return r.EngineRun > 0 && r.Step > 0 && r.Before > 0 && r.After == r.Before-1
	}
	return false
}

func encodeAppQueueRec(r *AppQueueRec, jseq uint64) ([]byte, error) {
	if !validAppQueueRec(r) {
		return nil, fmt.Errorf("journal: invalid application queue source")
	}
	return rlp.Encode(&appQueueRLP{Format: Format, JSeq: jseq, Version: r.Version, Sequence: r.Sequence, Request: r.Request, EngineRun: r.EngineRun, Step: r.Step, Action: r.Action, InputKind: r.InputKind, Input: bytesOrEmpty(r.Input), Before: r.Before, After: r.After, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs), Unavailable: r.Unavailable})
}

func decodeAppQueueRec(body []byte) (Record, error) {
	var w appQueueRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: application queue: %v", ErrRecord, err)
	}
	r := &AppQueueRec{Version: w.Version, Sequence: w.Sequence, Request: w.Request, EngineRun: w.EngineRun, Step: w.Step, Action: w.Action, InputKind: w.InputKind, Input: w.Input, Before: w.Before, After: w.After, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs), Unavailable: w.Unavailable}
	if w.Format != Format || !validAppQueueRec(r) {
		return Record{}, fmt.Errorf("%w: invalid application queue source", ErrRecord)
	}
	return Record{Kind: KindAppQueue, JSeq: w.JSeq, Body: r}, nil
}
