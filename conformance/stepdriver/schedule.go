package stepdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

var ErrTraceSchedule = errors.New("stepdriver: invalid trace input schedule")
var ErrTraceScheduleReservation = errors.New("stepdriver: input reservation boundary is not proven")

// TraceSchedule changes one external input in a recorded writer/engine run.
// Delay places Step after OtherStep; swap exchanges two external inputs.
// These operations do not change receipt clocks or manufacture timer inputs.
type TraceSchedule struct {
	Action    string `json:"action"`
	WriterRun string `json:"writer_run"`
	EngineRun uint64 `json:"engine_run"`
	Step      uint64 `json:"step"`
	OtherStep uint64 `json:"other_step,omitempty"`
}

// UnmarshalJSON rejects ambiguous or unsupported experiment fields.
func (s *TraceSchedule) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 {
		return ErrTraceSchedule
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrTraceSchedule
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return ErrTraceSchedule
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return ErrTraceSchedule
		}
		seen[name] = true
		switch name {
		case "action", "writer_run", "engine_run", "step", "other_step":
		default:
			return ErrTraceSchedule
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrTraceSchedule
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return ErrTraceSchedule
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrTraceSchedule
	}
	type plain TraceSchedule
	var out plain
	if json.Unmarshal(raw, &out) != nil {
		return ErrTraceSchedule
	}
	*s = TraceSchedule(out)
	return nil
}

// TraceInputPosition retains original coordinates alongside execution order.
// Removed positions stay visible as actual empty-input comparisons.
type TraceInputPosition struct {
	WriterRun     string `json:"writer_run"`
	EngineRun     uint64 `json:"engine_run"`
	Step          uint64 `json:"step"`
	Ordinal       uint64 `json:"reader_ordinal"`
	JSeq          uint64 `json:"source_seq"`
	ExecutionStep uint64 `json:"execution_step"`
	SlotStep      uint64 `json:"slot_step"`
	SlotOrdinal   uint64 `json:"slot_reader_ordinal"`
	SlotJSeq      uint64 `json:"slot_source_seq"`
	Removed       bool   `json:"removed,omitempty"`
}

type scheduleInput struct {
	position     TraceInputPosition
	body         *journal.StepRec
	previousMono int64
	receipt      int64
}

// PlanTraceSchedule validates the untouched source before arranging positions.
// It returns metadata only; it does not run a second consensus implementation.
// Swaps require recorded receipt before the preceding completed step of the
// earlier position. An unknown reservation boundary is refused, not guessed.
func PlanTraceSchedule(reader JournalReader, change TraceSchedule) ([]TraceInputPosition, error) {
	if reader == nil || change.WriterRun == "" || change.EngineRun == 0 || change.Step == 0 {
		return nil, ErrTraceSchedule
	}
	switch change.Action {
	case "drop":
		if change.OtherStep != 0 {
			return nil, ErrTraceSchedule
		}
	case "delay":
		if change.OtherStep <= change.Step {
			return nil, ErrTraceSchedule
		}
	case "swap":
		if change.OtherStep == 0 || change.OtherStep == change.Step {
			return nil, ErrTraceSchedule
		}
	default:
		return nil, ErrTraceSchedule
	}
	inputs := []scheduleInput{}
	writer := ""
	var engine, last, seq uint64
	var previousMono int64 = -1
	seen := map[answerCoordinate]bool{}
	source, other := -1, -1
	for ordinal := uint64(1); ; ordinal++ {
		rec, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if ordinal > MaxAnswerRecords {
			return nil, ErrTraceAnswerLimit
		}
		if b, ok := rec.Body.(*journal.SegmentRec); ok && b.Run != writer {
			writer, engine, last, seq, previousMono = b.Run, 0, 0, 0, -1
		}
		if writer == "" || rec.JSeq == 0 || seq != 0 && rec.JSeq != seq+1 {
			return nil, ErrTraceGap
		}
		seq = rec.JSeq
		switch b := rec.Body.(type) {
		case *journal.GapRec:
			return nil, ErrTraceGap
		case *journal.StepRec:
			if len(inputs) >= MaxAnswerSteps {
				return nil, ErrTraceAnswerLimit
			}
			key := answerCoordinate{writer, b.EngineRun, b.Step}
			if seen[key] || b.EngineRun == 0 || b.Step == 0 {
				return nil, ErrTraceGap
			}
			seen[key] = true
			if b.InputKind == inputlog.KindStart {
				engine, last, previousMono = b.EngineRun, b.Step-1, -1
			}
			if engine == 0 || b.EngineRun != engine || b.Step != last+1 {
				return nil, ErrTraceGap
			}
			// Only retain closed source metadata, not payloads or application answers.
			clone := *b
			clone.Input, clone.Env = nil, nil
			entry := scheduleInput{position: TraceInputPosition{WriterRun: writer, EngineRun: b.EngineRun, Step: b.Step, Ordinal: ordinal, JSeq: rec.JSeq}, body: &clone, previousMono: previousMono, receipt: -1}
			if writer == change.WriterRun && b.EngineRun == change.EngineRun {
				if b.Step == change.Step {
					if entry.receipt, err = externalReceipt(reader, writer, b); err != nil {
						return nil, err
					}
					source = len(inputs)
				}
				if b.Step == change.OtherStep {
					other = len(inputs)
					if change.Action == "swap" {
						if entry.receipt, err = externalReceipt(reader, writer, b); err != nil {
							return nil, err
						}
					}
				}
			}
			inputs = append(inputs, entry)
			last, previousMono = b.Step, int64(b.Mono)
		}
	}
	if source < 0 || change.Action != "drop" && other < 0 {
		return nil, ErrTraceSchedule
	}
	if change.Action != "drop" {
		lo, hi := source, other
		if lo > hi {
			lo, hi = hi, lo
		}
		for _, p := range inputs[lo : hi+1] {
			if p.position.WriterRun != change.WriterRun || p.position.EngineRun != change.EngineRun || p.body.InputKind == inputlog.KindStart || p.body.InputKind == inputlog.KindStop {
				return nil, ErrTraceSchedule
			}
		}
	}
	slots := make([]TraceInputPosition, len(inputs))
	for i, p := range inputs {
		slots[i] = p.position
	}
	switch change.Action {
	case "drop":
		inputs[source].position.Removed = true
	case "delay":
		moving := inputs[source]
		copy(inputs[source:other], inputs[source+1:other+1])
		inputs[other] = moving
	case "swap":
		earlier := source
		if other < earlier {
			earlier = other
		}
		bound := inputs[earlier].previousMono
		if bound < 0 || inputs[source].receipt < 0 || inputs[other].receipt < 0 || inputs[source].receipt >= bound || inputs[other].receipt >= bound {
			return nil, ErrTraceScheduleReservation
		}
		inputs[source], inputs[other] = inputs[other], inputs[source]
	}
	out := make([]TraceInputPosition, len(inputs))
	var run string
	var current uint64
	var n uint64
	for i, p := range inputs {
		if p.position.WriterRun != run || p.position.EngineRun != current {
			run, current, n = p.position.WriterRun, p.position.EngineRun, 0
		}
		n++
		p.position.ExecutionStep = n
		p.position.SlotStep = slots[i].Step
		p.position.SlotOrdinal = slots[i].Ordinal
		p.position.SlotJSeq = slots[i].JSeq
		out[i] = p.position
	}
	return out, nil
}

func externalReceipt(reader JournalReader, writer string, b *journal.StepRec) (int64, error) {
	if b.Via != "peer" {
		return 0, ErrTraceSchedule
	}
	switch b.InputKind {
	case inputlog.KindCapturedMessage:
		if _, err := resolveCaptured(reader, writer, b); err != nil {
			return 0, err
		}
		id, err := inputlog.CapturedReference(b.Input)
		if err != nil {
			return 0, err
		}
		frame, err := reader.(captureResolver).ResolveCapture(writer, id)
		if err != nil {
			return 0, err
		}
		if frame.Record.Mono < 0 || frame.Record.Offer != transport.OfferQueued {
			return 0, ErrTraceSchedule
		}
		// The frame and completed step use the same journal clock. RecvMono in
		// an inline transport input can have a different clock origin.
		return int64(frame.Record.Mono), nil
	case inputlog.KindMessage:
		in, err := inputlog.Decode(b.InputKind, b.Input, nil)
		if err != nil {
			return 0, err
		}
		if _, ok := in.(consensus.Message); !ok {
			return 0, ErrTraceSchedule
		}
		return -1, nil // No transport reservation timestamp is proven by inline bytes.
	}
	return 0, ErrTraceSchedule
}
