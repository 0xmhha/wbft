package stepdriver

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type scheduleRecords struct {
	records []journal.Record
	index   int
}

func (r *scheduleRecords) Next() (journal.Record, error) {
	if r.index == len(r.records) {
		return journal.Record{}, io.EOF
	}
	out := r.records[r.index]
	r.index++
	return out, nil
}
func (r *scheduleRecords) ResolveCapture(_ string, id uint64) (journal.CapturedFrame, error) {
	for _, rec := range r.records {
		if s, ok := rec.Body.(*journal.StepRec); ok && s.Step == id {
			payload, _ := rlp.Encode([]byte{0xc0})
			return journal.CapturedFrame{Record: &journal.MsgRec{Dir: journal.In, Capture: id, Code: uint64(codec.CodePrepare), Payload: payload, Mono: (s.Mono - 3) / 2, Offer: "queued"}, Peer: types.Address{1}}, nil
		}
	}
	return journal.CapturedFrame{}, journal.ErrCaptureMissing
}
func scheduleFixture(t *testing.T) []journal.Record {
	t.Helper()
	records := []journal.Record{{JSeq: 1, Body: &journal.SegmentRec{Identity: journal.Identity{Run: "writer"}}}}
	for n := uint64(1); n <= 6; n++ {
		kind, via := inputlog.KindTimeout, "timer"
		var raw []byte
		if n == 1 {
			kind, via = inputlog.KindStart, "internal"
		}
		if n == 3 || n == 5 {
			kind, via = inputlog.KindCapturedMessage, "peer"
			var err error
			raw, err = inputlog.EncodeCapturedMessage(consensus.Message{Code: codec.CodePrepare, Peer: types.Address{1}, RecvMono: 20}, n)
			if err != nil {
				t.Fatal(err)
			}
		}
		records = append(records, journal.Record{JSeq: n + 1, Body: &journal.StepRec{EngineRun: 1, Step: n, InputKind: kind, Input: raw, Via: via, Mono: time.Duration(n)}})
	}
	return records
}
func TestTraceSchedulePreservesSourceAndExplicitEmptyPositions(t *testing.T) {
	for _, c := range []struct {
		action string
		other  uint64
		want   []uint64
	}{{"drop", 0, []uint64{1, 2, 3, 4, 5, 6}}, {"delay", 5, []uint64{1, 2, 4, 5, 3, 6}}, {"swap", 5, []uint64{1, 2, 5, 4, 3, 6}}} {
		t.Run(c.action, func(t *testing.T) {
			records := scheduleFixture(t)
			before := append([]byte(nil), records[3].Body.(*journal.StepRec).Input...)
			result, err := PlanTraceSchedule(&scheduleRecords{records: records}, TraceSchedule{Action: c.action, WriterRun: "writer", EngineRun: 1, Step: 3, OtherStep: c.other})
			if err != nil || len(result) != 6 {
				t.Fatal(result, err)
			}
			var steps []uint64
			for i, p := range result {
				steps = append(steps, p.Step)
				if p.Ordinal != p.Step+1 || p.JSeq != p.Step+1 || p.ExecutionStep != uint64(i+1) || p.SlotStep != uint64(i+1) || p.SlotJSeq != uint64(i+2) || p.WriterRun != "writer" || p.EngineRun != 1 || p.Removed != (c.action == "drop" && p.Step == 3) {
					t.Fatal("source or execution coordinate changed", p)
				}
			}
			if !reflect.DeepEqual(steps, c.want) || !reflect.DeepEqual(records[3].Body.(*journal.StepRec).Input, before) {
				t.Fatal(steps, records)
			}
		})
	}
}
func TestTraceScheduleRefusesUnprovenReservationAndInternalInputs(t *testing.T) {
	for _, change := range []string{"receipt_after_boundary", "inline_clock", "internal", "gap", "engine", "missing", "backward_delay", "unknown_action", "lifecycle"} {
		t.Run(change, func(t *testing.T) {
			records := scheduleFixture(t)
			spec := TraceSchedule{Action: "swap", WriterRun: "writer", EngineRun: 1, Step: 3, OtherStep: 5}
			switch change {
			case "receipt_after_boundary":
				records[5].Body.(*journal.StepRec).Mono = 30
			case "inline_clock":
				raw, _ := inputlog.Encode(consensus.Message{Peer: types.Address{1}, RecvMono: 0})
				records[5].Body.(*journal.StepRec).InputKind = inputlog.KindMessage
				records[5].Body.(*journal.StepRec).Input = raw
			case "internal":
				records[3].Body.(*journal.StepRec).Via = "internal"
			case "gap":
				records[4].Body.(*journal.StepRec).Step = 9
			case "engine":
				spec.EngineRun = 2
			case "missing":
				spec.Step = 99
			case "backward_delay":
				spec.Action = "delay"
				spec.Step = 5
				spec.OtherStep = 3
			case "unknown_action":
				spec.Action = "invent"
			case "lifecycle":
				spec.Action = "delay"
				records[4].Body.(*journal.StepRec).InputKind = inputlog.KindStop
			}
			if _, err := PlanTraceSchedule(&scheduleRecords{records: records}, spec); err == nil {
				t.Fatal("invalid or causally unproven plan accepted")
			}
		})
	}
	records := scheduleFixture(t)
	records = append(records, journal.Record{JSeq: 8, Body: &journal.GapRec{Dropped: 1}})
	if _, err := PlanTraceSchedule(&scheduleRecords{records: records}, TraceSchedule{Action: "drop", WriterRun: "writer", EngineRun: 1, Step: 3}); !errors.Is(err, ErrTraceGap) {
		t.Fatal(err)
	}
}

func TestScheduledReservationsRequireActualPreviousOutput(t *testing.T) {
	ledger := &reservationLedger{}
	ledger.reset()
	request := consensus.Request{Block: nil}
	if allowed, err := ledger.allowed(request, "internal", types.Address{}); allowed || err == nil {
		t.Fatal("invalid internal request accepted", allowed, err)
	}
	timer := consensus.ArmTimer{Kind: consensus.RoundTimer, Gen: 7, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(0)}, Round: types.RoundFromUint64(0)}
	input := consensus.Timeout{Kind: timer.Kind, Gen: timer.Gen, View: timer.View, Round: timer.Round}
	if ok, err := ledger.allowed(input, "timer", types.Address{}); err != nil || ok {
		t.Fatal(ok, err)
	}
	if err := ledger.produced([]consensus.Output{timer}); err != nil {
		t.Fatal(err)
	}
	altered := input
	altered.View.Sequence = types.HeightFromUint64(2)
	if ok, err := ledger.allowed(altered, "timer", types.Address{}); err != nil || ok {
		t.Fatal("generation alone accepted wrong timer context", ok, err)
	}
	if ok, err := ledger.allowed(input, "timer", types.Address{}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := ledger.allowed(input, "timer", types.Address{}); err != nil || ok {
		t.Fatal("timer reservation consumed twice", ok, err)
	}
}

func TestTraceScheduleJSONRejectsAmbiguousAndUnsupportedChanges(t *testing.T) {
	for _, raw := range []string{`{"action":"drop","action":"delay"}`, `{"action":"drop","payload":"injection"}`, `{"action":"drop","step":1.5}`, `{"action":"drop","step":"1"}`, `null`, `[]`, `{} {}`} {
		var s TraceSchedule
		if json.Unmarshal([]byte(raw), &s) == nil {
			t.Fatal("ambiguous schedule accepted", raw)
		}
	}
	var s TraceSchedule
	if err := json.Unmarshal([]byte(`{"action":"drop","writer_run":"writer","engine_run":1,"step":3}`), &s); err != nil || s.Step != 3 {
		t.Fatal(s, err)
	}
}
