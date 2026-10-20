package journal

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
)

// TimerTraceVersion identifies the measured scheduler operation journal.
const TimerTraceVersion uint64 = 1

// TimerRec is a scheduler mutation measured under its queue mutex. Sequence
// orders equal timestamps. Input is the full encoded Timeout for its arm.
// Output is one-based; zero and Step zero identify lifecycle or WAL operations.
type TimerRec struct {
	Sequence                         uint64
	EngineRun, Step, Output          uint64
	ArmEngineRun, ArmStep, ArmOutput uint64
	Source, Action                   string
	Mono                             time.Duration
	WallNs                           int64
	EntryMono, Deadline              time.Duration
	Input                            []byte
	Kinds                            []uint64
}
type timerRLP struct {
	Format, JSeq, Sequence            uint64
	EngineRun, Step, Output           uint64
	ArmEngineRun, ArmStep, ArmOutput  uint64
	Source, Action                    string
	Mono, WallNs, EntryMono, Deadline uint64
	Input                             []byte
	Kinds                             []uint64
}

func validTimerRec(r *TimerRec) bool {
	if r.Sequence == 0 || r.EngineRun == 0 || r.Mono < 0 || r.EntryMono < 0 || r.EntryMono > r.Mono || r.Deadline < 0 {
		return false
	}
	switch r.Source {
	case "core", "restore", "lifecycle", "dequeue":
	default:
		return false
	}
	switch r.Action {
	case "arm", "replace", "cancelled", "queued", "pop":
		return len(r.Input) > 0 && r.ArmEngineRun > 0 && len(r.Kinds) == 0
	case "cancel":
		if len(r.Input) != 0 || len(r.Kinds) > 4 {
			return false
		}
		seen := map[uint64]bool{}
		for _, kind := range r.Kinds {
			if kind > 3 || seen[kind] {
				return false
			}
			seen[kind] = true
		}
		return true
	case "clear":
		return len(r.Input) == 0 && len(r.Kinds) == 0
	default:
		return false
	}
}
func encodeTimerRec(r *TimerRec, jseq uint64) ([]byte, error) {
	if !validTimerRec(r) {
		return nil, fmt.Errorf("journal: invalid timer operation")
	}
	return rlp.Encode(&timerRLP{Format: Format, JSeq: jseq, Sequence: r.Sequence, EngineRun: r.EngineRun, Step: r.Step, Output: r.Output, ArmEngineRun: r.ArmEngineRun, ArmStep: r.ArmStep, ArmOutput: r.ArmOutput, Source: r.Source, Action: r.Action, Mono: uint64(r.Mono), WallNs: uint64(r.WallNs), EntryMono: uint64(r.EntryMono), Deadline: uint64(r.Deadline), Input: bytesOrEmpty(r.Input), Kinds: nonNilTimerKinds(r.Kinds)})
}
func decodeTimerRec(body []byte) (Record, error) {
	var w timerRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: timer: %v", ErrRecord, err)
	}
	r := &TimerRec{Sequence: w.Sequence, EngineRun: w.EngineRun, Step: w.Step, Output: w.Output, ArmEngineRun: w.ArmEngineRun, ArmStep: w.ArmStep, ArmOutput: w.ArmOutput, Source: w.Source, Action: w.Action, Mono: time.Duration(w.Mono), WallNs: int64(w.WallNs), EntryMono: time.Duration(w.EntryMono), Deadline: time.Duration(w.Deadline), Input: w.Input, Kinds: w.Kinds}
	if w.Format != Format || !validTimerRec(r) {
		return Record{}, fmt.Errorf("%w: invalid timer operation", ErrRecord)
	}
	return Record{Kind: KindTimer, JSeq: w.JSeq, Body: r}, nil
}

func nonNilTimerKinds(kinds []uint64) []uint64 {
	if kinds == nil {
		return []uint64{}
	}
	return kinds
}
