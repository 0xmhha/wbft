package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
)

// FinalizeSourceVersion identifies detached application finalization sources.
const FinalizeSourceVersion uint64 = 1

// FinalizeRec binds a commit-queue task to its original core output, actual
// application call and application-input queue notification. It does not prove
// application state execution, physical I/O or a complete runtime schedule.
type FinalizeRec struct {
	Version, Sequence, Task uint64
	EngineRun, Step, Output uint64
	Action                  string
	Before, After           uint64
	Arguments, Input        []byte
	HasError                bool
	QueueRun                string
	QueueRequest            uint64
	Mono                    time.Duration
	WallNs                  int64
	Unavailable             string
}

type finalizeRLP struct {
	Format, JSeq, Version, Sequence, Task uint64
	EngineRun, Step, Output               uint64
	Action                                string
	Before, After                         uint64
	Arguments, Input                      []byte
	HasError                              uint64
	QueueRun                              string
	QueueRequest, Mono, WallNs            uint64
	Unavailable                           string
}

func validFinalizeRec(r *FinalizeRec) bool {
	if r.Version != FinalizeSourceVersion || r.Mono < 0 {
		return false
	}
	switch r.Unavailable {
	case "", "metadata_exhausted", "owner_unavailable", "argument_encoding", "queue_source_unavailable":
	default:
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	if r.Unavailable == "" && (r.Task == 0 || r.EngineRun == 0 || r.Step == 0 || r.Output == 0) {
		return false
	}
	if r.Action != "notify" && (len(r.Input) != 0 || r.QueueRun != "" || r.QueueRequest != 0) {
		return false
	}
	if r.Action != "enqueue" && r.Action != "enter" && len(r.Arguments) != 0 {
		return false
	}
	if r.Action != "return" && r.Action != "notify" && r.HasError {
		return false
	}
	switch r.Action {
	case "enqueue":
		return r.Task == r.Sequence && r.Before != ^uint64(0) && r.After == r.Before+1 && (len(r.Arguments) > 0 || r.Unavailable != "")
	case "dequeue":
		return r.Before > 0 && r.After == r.Before-1
	case "enter":
		return r.Before == 0 && r.After == 0 && (len(r.Arguments) > 0 || r.Unavailable != "")
	case "return":
		return r.Before == 0 && r.After == 0
	case "notify":
		return r.Before == 0 && r.After == 0 && (r.Unavailable != "" || len(r.Input) > 0 && r.QueueRun != "" && r.QueueRequest > 0)
	}
	return false
}

func encodeFinalizeRec(r *FinalizeRec, jseq uint64) ([]byte, error) {
	if !validFinalizeRec(r) {
		return nil, fmt.Errorf("journal: invalid finalization source")
	}
	return rlp.Encode(&finalizeRLP{Format: Format, JSeq: jseq, Version: r.Version, Sequence: r.Sequence, Task: r.Task, EngineRun: r.EngineRun, Step: r.Step, Output: r.Output, Action: r.Action, Before: r.Before, After: r.After, Arguments: bytesOrEmpty(r.Arguments), Input: bytesOrEmpty(r.Input), HasError: boolUint(r.HasError), QueueRun: r.QueueRun, QueueRequest: r.QueueRequest, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs), Unavailable: r.Unavailable})
}

func decodeFinalizeRec(body []byte) (Record, error) {
	var w finalizeRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: finalization source: %v", ErrRecord, err)
	}
	r := &FinalizeRec{Version: w.Version, Sequence: w.Sequence, Task: w.Task, EngineRun: w.EngineRun, Step: w.Step, Output: w.Output, Action: w.Action, Before: w.Before, After: w.After, Arguments: w.Arguments, Input: w.Input, HasError: w.HasError == 1, QueueRun: w.QueueRun, QueueRequest: w.QueueRequest, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs), Unavailable: w.Unavailable}
	if w.Format != Format || w.HasError > 1 || !validFinalizeRec(r) {
		return Record{}, fmt.Errorf("%w: invalid finalization source", ErrRecord)
	}
	return Record{Kind: KindFinalize, JSeq: w.JSeq, Body: r}, nil
}
