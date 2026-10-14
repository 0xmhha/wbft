package journal

import (
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestMessageIOIntervalRetainsEndpointsAndLegacyAbsence(t *testing.T) {
	m := &MsgRec{Dir: Out, Mono: 10 * time.Second, WallNs: 90, Code: 0x13, Payload: []byte{1}, Write: "ok"}
	raw, err := encodeBody(Record{Body: m}, 11)
	if err != nil {
		t.Fatal(err)
	}
	items, err := rlp.ListItems(raw)
	if err != nil || len(items) != 18 {
		t.Fatal("legacy message encoding changed", len(items), err)
	}
	old, err := decodeBody(KindMsg, raw)
	if err != nil || old.Body.(*MsgRec).IO != nil {
		t.Fatal("legacy point timestamp became an interval", err)
	}
	// Known monotonic zero and a wall-clock regression are preserved exactly.
	m.IO = &IOInterval{StartMono: 0, EndMono: time.Second, StartWallNs: 100, EndWallNs: 90}
	raw, err = encodeBody(Record{Body: m}, 11)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeBody(KindMsg, raw)
	if err != nil || !reflect.DeepEqual(r.Body.(*MsgRec).IO, m.IO) {
		t.Fatal("measured interval changed", err)
	}
	items, err = rlp.ListItems(raw)
	if err != nil || len(items) != 19 {
		t.Fatal("I/O interval missing", len(items), err)
	}
	for _, bad := range [][]uint64{{1}, {1, 2, 3}, {1, 2, 3, 4, 5}, {2, 100, 1, 90}, {0, 100, uint64(m.Mono) + 1, 90}, {0, 100, ^uint64(0), 90}} {
		x, err := rlp.Encode(bad)
		if err != nil {
			t.Fatal(err)
		}
		changed := make([][]byte, len(items))
		for i, item := range items {
			changed[i] = item
		}
		changed[18] = x
		if _, err := decodeBody(KindMsg, rlp.EncodeList(changed...)); err == nil {
			t.Fatal("invalid interval accepted", bad)
		}
	}
	m.IO.StartMono = -1
	if _, err := encodeBody(Record{Body: m}, 11); err == nil {
		t.Fatal("negative monotonic interval accepted")
	}
}

func TestMessageIOMetadataRespectsQueueBudget(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/j", QueueRecords: 10, QueueBytes: 150}, Identity{Run: "io-budget"})
	if err != nil {
		t.Fatal(err)
	}
	w.Put(Record{Body: &MsgRec{Dir: Out, Mono: 2, Code: 0x13, Write: "ok", Payload: []byte{1}, IO: &IOInterval{EndMono: 1}}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rs, err := ReadAll(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	var dropped uint64
	for _, r := range rs {
		if g, ok := r.Body.(*GapRec); ok {
			dropped += g.Dropped
		}
		if _, ok := r.Body.(*MsgRec); ok {
			t.Fatal("I/O metadata exceeded queue budget without a gap")
		}
	}
	if dropped != 1 {
		t.Fatal("missing overflow evidence", dropped)
	}
}
