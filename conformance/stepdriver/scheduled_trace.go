package stepdriver

import (
	"bytes"
	"io"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

const MaxScheduledInputBytes = 256 << 20
const MaxReservedInputs = 100000

type scheduledEntry struct {
	original, slot *journal.StepRec
	position       TraceInputPosition
}
type scheduledJournal struct {
	source  JournalReader
	records []journal.Record
	entries map[*journal.StepRec]scheduledEntry
	index   int
}

func (s *scheduledJournal) Next() (journal.Record, error) {
	if s.index == len(s.records) {
		return journal.Record{}, io.EOF
	}
	r := s.records[s.index]
	s.index++
	return r, nil
}
func (s *scheduledJournal) ResolveCapture(run string, id uint64) (journal.CapturedFrame, error) {
	resolver, ok := s.source.(captureResolver)
	if !ok {
		return journal.CapturedFrame{}, ErrTraceInvalidInput
	}
	return resolver.ResolveCapture(run, id)
}
func newScheduledJournal(source JournalReader, change TraceSchedule) (*scheduledJournal, error) {
	s := &scheduledJournal{source: source, entries: map[*journal.StepRec]scheduledEntry{}}
	total := 0
	for n := 0; ; n++ {
		rec, err := source.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if n >= MaxAnswerRecords {
			return nil, ErrTraceAnswerLimit
		}
		switch b := rec.Body.(type) {
		case *journal.StepRec:
			if len(b.Input) > MaxScheduledInputBytes-total {
				return nil, ErrTraceAnswerLimit
			}
			total += len(b.Input)
			for _, answer := range b.Env {
				if len(answer) > MaxScheduledInputBytes-total {
					return nil, ErrTraceAnswerLimit
				}
				total += len(answer)
			}
		case *journal.SegmentRec:
			if len(b.Core.ChainConfig) > MaxScheduledInputBytes-total || len(b.Core.ChainConfig) > MaxApplicationAnswerBytes {
				return nil, ErrTraceAnswerLimit
			}
			total += len(b.Core.ChainConfig)
		case *journal.GapRec:
		default:
			rec.Body = nil // Wire bytes stay behind the original capture resolver.
		}
		s.records = append(s.records, rec)
	}
	plan, err := PlanTraceSchedule(s, change)
	if err != nil {
		return nil, err
	}
	s.index = 0
	originals := map[uint64]*journal.StepRec{}
	for i, rec := range s.records {
		if b, ok := rec.Body.(*journal.StepRec); ok {
			originals[uint64(i+1)] = b
		}
	}
	at := 0
	for i, rec := range s.records {
		slot, ok := rec.Body.(*journal.StepRec)
		if !ok {
			continue
		}
		p := plan[at]
		original := originals[p.Ordinal]
		if original == nil {
			return nil, ErrTraceSchedule
		}
		clone := *original
		clone.Step = slot.Step
		s.entries[&clone] = scheduledEntry{original, slot, p}
		s.records[i].Body = &clone
		at++
	}
	return s, nil
}

// reservationLedger records only events actually produced by prior handlers.
// It never signs, sends, or implicitly executes a reserved input.
type reservationLedger struct {
	queue      [][]byte
	broadcasts []*codec.Message
	timers     map[[2]uint64][]byte
}

func (l *reservationLedger) reset() {
	l.queue = nil
	l.broadcasts = nil
	l.timers = map[[2]uint64][]byte{}
}
func (l *reservationLedger) produced(outs []consensus.Output) error {
	for _, out := range outs {
		switch o := out.(type) {
		case consensus.Schedule:
			raw, err := inputlog.Encode(o.In)
			if err != nil {
				return err
			}
			if len(l.queue)+len(l.broadcasts)+len(l.timers) >= MaxReservedInputs {
				return ErrTraceAnswerLimit
			}
			l.queue = append(l.queue, raw)
		case consensus.Broadcast:
			if len(l.queue)+len(l.broadcasts)+len(l.timers) >= MaxReservedInputs {
				return ErrTraceAnswerLimit
			}
			l.broadcasts = append(l.broadcasts, o.Msg)
		case consensus.ArmTimer:
			if len(l.queue)+len(l.broadcasts)+len(l.timers) >= MaxReservedInputs {
				return ErrTraceAnswerLimit
			}
			raw, err := inputlog.Encode(consensus.Timeout{Kind: o.Kind, View: o.View, Round: o.Round, Gen: o.Gen, Msg: o.Msg})
			if err != nil {
				return err
			}
			l.timers[[2]uint64{uint64(o.Kind), o.Gen}] = raw
		}
	}
	return nil
}
func normalizedMessage(m *codec.Message) ([]byte, error) {
	if m == nil {
		return nil, ErrTraceInvalidInput
	}
	clone := *m
	clone.Signature = nil
	clone.Seal = nil
	clone.RoundChanges = make([]*codec.Message, len(m.RoundChanges))
	clone.Prepares = make([]*codec.Message, len(m.Prepares))
	for i, x := range m.RoundChanges {
		raw, err := normalizedMessage(x)
		if err != nil {
			return nil, err
		}
		clone.RoundChanges[i], err = codec.DecodeMessage(x.Code, raw)
		if err != nil {
			return nil, err
		}
	}
	for i, x := range m.Prepares {
		raw, err := normalizedMessage(x)
		if err != nil {
			return nil, err
		}
		clone.Prepares[i], err = codec.DecodeMessage(x.Code, raw)
		if err != nil {
			return nil, err
		}
	}
	return codec.EncodeMessage(&clone)
}
func (l *reservationLedger) allowed(in consensus.Input, via string, self types.Address) (bool, error) {
	switch v := in.(type) {
	case consensus.Timeout:
		key := [2]uint64{uint64(v.Kind), v.Gen}
		expected, ok := l.timers[key]
		if !ok {
			return false, nil
		}
		actual, err := inputlog.Encode(v)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(actual, expected) {
			return false, nil
		}
		delete(l.timers, key)
		return true, nil
	case consensus.Message:
		if v.Peer != self {
			return true, nil
		}
		m, err := codec.DecodeMessage(v.Code, v.Payload)
		if err != nil {
			return false, err
		}
		raw, err := normalizedMessage(m)
		if err != nil {
			return false, err
		}
		for i, b := range l.broadcasts {
			candidate, err := normalizedMessage(b)
			if err != nil {
				return false, err
			}
			if bytes.Equal(raw, candidate) {
				l.broadcasts = append(l.broadcasts[:i], l.broadcasts[i+1:]...)
				return true, nil
			}
		}
		return false, nil
	case consensus.Replay:
	case consensus.Request:
		if v.Block == nil || v.Block.Header == nil {
			return false, ErrTraceInvalidInput
		}
		if via != "internal" {
			return true, nil
		}
	case consensus.BroadcastFailed:
		for i, b := range l.broadcasts {
			if b.Code == v.Code && b.View.Sequence.Cmp(v.View.Sequence) == 0 && b.View.Round.Cmp(v.View.Round) == 0 {
				l.broadcasts = append(l.broadcasts[:i], l.broadcasts[i+1:]...)
				return true, nil
			}
		}
		return false, nil
	default:
		return true, nil
	}
	raw, err := inputlog.Encode(in)
	if err != nil {
		return false, err
	}
	for i, candidate := range l.queue {
		if bytes.Equal(raw, candidate) {
			l.queue = append(l.queue[:i], l.queue[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func scheduledEmpty(core *consensus.State, b *journal.StepRec, context bool, reason string) (StepResult, error) {
	d, err := inputlog.OutDigest(nil)
	if err != nil {
		return StepResult{}, err
	}
	return StepResult{ContextAnswers: context, RecordedInputKind: b.InputKind, Omitted: true, SuppressionReason: reason, EngineRun: b.EngineRun, Step: b.Step, Outputs: []consensus.Output{}, OutDigest: d, Match: d == b.OutDigest && consensus.ValsetDigest(core.Snapshot().Validators) == b.ValsetDigest}, nil
}
func decodeTraceInput(b *journal.StepRec, captured *consensus.Message) (consensus.Input, error) {
	return inputlog.Decode(b.InputKind, b.Input, func(uint64) ([]byte, error) {
		if captured == nil {
			return nil, ErrTraceMissingInput
		}
		return captured.Payload, nil
	})
}
