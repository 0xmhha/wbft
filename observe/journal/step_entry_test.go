package journal

import (
	"github.com/0xmhha/wbft/codec/rlp"
	"reflect"
	"testing"
	"time"
)

func TestStepEntryKnownZeroAndLegacyAbsence(t *testing.T) {
	s := step(7)
	raw, e := encodeBody(Record{Body: s}, 91)
	if e != nil {
		t.Fatal(e)
	}
	items, e := rlp.ListItems(raw)
	if e != nil || len(items) != 15 {
		t.Fatal("legacy encoding changed", len(items), e)
	}
	old, e := decodeBody(KindStep, raw)
	if e != nil || old.Body.(*StepRec).Entry != nil {
		t.Fatal("legacy completion substituted for entry", e)
	}
	s.Entry = &StepMoment{Mono: 0, WallNs: 1234}
	raw, e = encodeBody(Record{Body: s}, 91)
	if e != nil {
		t.Fatal(e)
	}
	rec, e := decodeBody(KindStep, raw)
	if e != nil || !reflect.DeepEqual(rec.Body.(*StepRec).Entry, s.Entry) {
		t.Fatal("measured zero entry lost", e)
	}
	items, e = rlp.ListItems(raw)
	if e != nil || len(items) != 16 {
		t.Fatal("entry not encoded", e)
	}
	for _, values := range [][]uint64{{1}, {1, 2, 3}, {uint64(s.Mono + time.Second), 2}, {^uint64(0), 2}} {
		entry, e := rlp.Encode(values)
		if e != nil {
			t.Fatal(e)
		}
		bad := make([][]byte, len(items))
		for i, x := range items {
			bad[i] = x
		}
		bad[15] = entry
		if _, e = decodeBody(KindStep, rlp.EncodeList(bad...)); e == nil {
			t.Fatal("invalid entry accepted", values)
		}
	}
	s.Entry.Mono = s.Mono + time.Nanosecond
	if _, e = encodeBody(Record{Body: s}, 91); e == nil {
		t.Fatal("producer accepted completion before entry")
	}
}
