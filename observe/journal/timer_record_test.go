package journal

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"testing"
	"time"
)

func TestTimerRecordPreservesOperationAndFullOpaqueInput(t *testing.T) {
	original := &TimerRec{Sequence: 4, EngineRun: 2, Step: 7, Output: 3, ArmEngineRun: 2, ArmStep: 5, ArmOutput: 2, Source: "core", Action: "queued", Mono: 20 * time.Nanosecond, WallNs: 123, EntryMono: 1, Deadline: 10, Input: []byte{0xc0}}
	raw, err := encodeBody(Record{Body: original}, 17)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeBody(KindTimer, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := record.Body.(*TimerRec)
	if record.JSeq != 17 || got.Sequence != 4 || got.Mono != original.Mono || got.ArmStep != 5 || got.Output != 3 || !bytes.Equal(got.Input, original.Input) {
		t.Fatal(record, got)
	}
	for _, variant := range []string{"sequence", "engine", "negative", "source", "action", "missing_input", "invalid_kinds"} {
		bad := *original
		switch variant {
		case "sequence":
			bad.Sequence = 0
		case "engine":
			bad.EngineRun = 0
		case "negative":
			bad.Mono = -1
		case "source":
			bad.Source = "unknown"
		case "action":
			bad.Action = "unknown"
		case "missing_input":
			bad.Input = nil
		case "invalid_kinds":
			bad.Kinds = []uint64{9}
		}
		if _, err := encodeBody(Record{Body: &bad}, 17); err == nil {
			t.Fatal("invalid timer record accepted", variant)
		}
	}
	cancel := &TimerRec{Sequence: 5, EngineRun: 2, Step: 8, Output: 2, Source: "core", Action: "cancel", Kinds: []uint64{0, 1, 2}, Mono: 21}
	raw, err = encodeBody(Record{Body: cancel}, 18)
	if err != nil {
		t.Fatal(err)
	}
	record, err = decodeBody(KindTimer, raw)
	if err != nil || len(record.Body.(*TimerRec).Kinds) != 3 {
		t.Fatal(record, err)
	}
}
func TestTimerCapabilityDoesNotAlterLegacySegmentEncoding(t *testing.T) {
	original := ident()
	segment := &SegmentRec{Identity: original}
	raw, err := encodeBody(Record{Body: segment}, 1)
	if err != nil {
		t.Fatal(err)
	}
	items, err := rlp.ListItems(raw)
	if err != nil || len(items) != 18 {
		t.Fatal(len(items), err)
	}
	record, err := decodeBody(KindSegment, raw)
	if err != nil || record.Body.(*SegmentRec).Core.TimerTrace != 0 {
		t.Fatal(record, err)
	}
	segment.Core.TimerTrace = TimerTraceVersion
	raw, err = encodeBody(Record{Body: segment}, 1)
	if err != nil {
		t.Fatal(err)
	}
	items, err = rlp.ListItems(raw)
	if err != nil || len(items) != 19 {
		t.Fatal(len(items), err)
	}
	record, err = decodeBody(KindSegment, raw)
	if err != nil || record.Body.(*SegmentRec).Core.TimerTrace != 1 {
		t.Fatal(record, err)
	}
}

func TestTimerOperationsSurviveSegmentRotationAndBundle(t *testing.T) {
	fs := fsys.NewMem()
	id := ident()
	id.Core.TimerTrace = TimerTraceVersion
	writer, err := Open(Options{FS: fs, Dir: "/timers", Synchronous: true, SegmentBytes: 800}, id)
	if err != nil {
		t.Fatal(err)
	}
	if !writer.TimerTraceEnabled() {
		t.Fatal("timer capability absent")
	}
	for i := uint64(1); i <= 6; i++ {
		writer.Put(Record{Body: step(i)})
		writer.Put(Record{Body: &TimerRec{Sequence: i, EngineRun: 1, Step: i, Output: 1, ArmEngineRun: 1, ArmStep: i, ArmOutput: 1, Source: "core", Action: "arm", Mono: time.Duration(i) * time.Millisecond, EntryMono: time.Duration(i) * time.Millisecond, Deadline: time.Duration(i+1) * time.Millisecond, Input: []byte{0xc0}}})
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/timers")
	if err != nil {
		t.Fatal(err)
	}
	timerCount := 0
	for _, rec := range records {
		if _, ok := rec.Body.(*TimerRec); ok {
			timerCount++
		}
		if seg, ok := rec.Body.(*SegmentRec); ok && seg.Core.TimerTrace != 1 {
			t.Fatal("rotated capability lost", seg)
		}
	}
	if timerCount != 6 {
		t.Fatal("timer records lost", timerCount)
	}
	var bundle bytes.Buffer
	if _, err = WriteBundle(fs, "/timers", &bundle, BundleOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadBundle(&bundle, fs, "/restored-timers"); err != nil {
		t.Fatal(err)
	}
	restored, err := ReadAll(fs, "/restored-timers")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != len(records) {
		t.Fatal("bundle records changed", len(restored), len(records))
	}
}
