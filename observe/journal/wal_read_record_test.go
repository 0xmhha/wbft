package journal

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
)

func walReadFixture(t *testing.T) *WALReadRec {
	t.Helper()
	fs := fsys.NewMem()
	l, _, err := wal.Open(fs, "/original-wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.AppendSync(wal.Record{Format: 1, Kind: 2, Body: []byte("normal-record")}); err != nil {
		t.Fatal(err)
	}
	_, _, source, err := l.ReadAllObserved("original-reader", wal.ReadSourceLimits{Frames: 8, Bytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return &WALReadRec{Source: source, Mono: uint64(23 * time.Second), WallNs: ^uint64(0)}
}
func TestWALReadRecordStrictOriginalFrames(t *testing.T) {
	r := walReadFixture(t)
	r.Source.Sequence = 1<<53 + 1
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindWALRead, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*WALReadRec)
	if decoded.JSeq != ^uint64(0) || back.Source.Sequence != r.Source.Sequence || back.Source.Namespace != r.Source.Namespace || back.Source.Log != r.Source.Log || back.WallNs != r.WallNs || back.Source.Frames[0].Position != r.Source.Frames[0].Position || !bytes.Equal(back.Source.Frames[0].Bytes, r.Source.Frames[0].Bytes) {
		t.Fatal("original read identity changed", back)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("durable bytes changed", err)
	}
	var wire walReadRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*walReadRLP){
		func(w *walReadRLP) { w.Format++ }, func(w *walReadRLP) { w.Version++ }, func(w *walReadRLP) { w.Log = 0 }, func(w *walReadRLP) { w.Sequence = 0 }, func(w *walReadRLP) { w.Namespace = "" }, func(w *walReadRLP) { w.Error = "unknown" }, func(w *walReadRLP) { w.Unavailable = "unknown" }, func(w *walReadRLP) { w.Mono = 1 << 63 }, func(w *walReadRLP) { w.Frames[0].Offset++ }, func(w *walReadRLP) { w.Frames[0].Offset = 1 << 63 }, func(w *walReadRLP) { w.Frames[0].Bytes[0] ^= 1 }, func(w *walReadRLP) { w.Frames[0].Bytes[4] ^= 1 }, func(w *walReadRLP) { w.Frames = append(w.Frames, w.Frames[0]) },
	} {
		c := wire
		c.Frames = slices.Clone(wire.Frames)
		for i := range c.Frames {
			c.Frames[i].Bytes = bytes.Clone(c.Frames[i].Bytes)
		}
		change(&c)
		bad, e := rlp.Encode(&c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := decodeBody(KindWALRead, bad); e == nil {
			t.Fatal("copied contradictory metadata accepted", c)
		}
	}
}
func TestWALReadRecordBudgetClassifiesGap(t *testing.T) {
	r := walReadFixture(t)
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/read-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	if size(Record{Body: r}) < 512 || monoOf(Record{Body: r}) != time.Duration(r.Mono) {
		t.Fatal("WAL read bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/read-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if g, ok := rec.Body.(*GapRec); ok {
			for _, k := range g.ByKind {
				if k.Kind == uint64(KindWALRead) && k.Count == 1 && g.FirstMono == time.Duration(r.Mono) && g.LastMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("classified WAL read gap missing")
}
