package journal

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"testing"
	"time"
)

func TestSelectionRecordStrictConditionalIdentity(t *testing.T) {
	r := &SelectionRec{Version: SelectionSourceVersion, Sequence: 1<<53 + 1, Selection: 1<<53 + 1, EngineRun: 1, Step: 1, Action: "select", Lane: "none", Internal: InputProbe{State: "empty"}, App: InputProbe{State: "empty"}, Timer: InputProbe{State: "empty"}, Inbox: InputProbe{State: "empty"}, NextHeight: "disabled", WallNs: ^uint64(0)}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindSelection, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*SelectionRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Selection != r.Selection || back.WallNs != r.WallNs {
		t.Fatal("portable identity changed", decoded)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("wire changed", err)
	}
	var wire selectionRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*selectionRLP){func(w *selectionRLP) { w.Format++ }, func(w *selectionRLP) { w.Source.Version++ }, func(w *selectionRLP) { w.Source.Selection++ }, func(w *selectionRLP) { w.Source.Sequence = 0 }, func(w *selectionRLP) { w.Source.Internal.State = "unknown" }, func(w *selectionRLP) { w.Source.Internal.Mono = 1 << 63 }, func(w *selectionRLP) { w.Source.Action = "unknown" }, func(w *selectionRLP) { w.Source.Random = 2 }, func(w *selectionRLP) { w.Source.Choice = 2 }, func(w *selectionRLP) { w.Source.Unavailable = "unknown" }, func(w *selectionRLP) { w.Source.Source = 1 }} {
		c := wire
		alter(&c)
		body, e := rlp.Encode(&c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := decodeBody(KindSelection, body); e == nil {
			t.Fatal("invalid source accepted", c)
		}
	}
}

func TestSelectionRecordBudgetClassifiesGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/selection-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	r := &SelectionRec{Version: SelectionSourceVersion, Sequence: 1, Selection: 1, EngineRun: 1, Step: 1, Action: "select", Lane: "none", Internal: InputProbe{State: "empty"}, App: InputProbe{State: "empty"}, Timer: InputProbe{State: "empty"}, Inbox: InputProbe{State: "empty"}, NextHeight: "disabled", Mono: uint64(23 * time.Second)}
	if monoOf(Record{Body: r}) != time.Duration(r.Mono) || size(Record{Body: r}) < 512 {
		t.Fatal("selection bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/selection-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if g, ok := record.Body.(*GapRec); ok {
			for _, k := range g.ByKind {
				if k.Kind == uint64(KindSelection) && k.Count == 1 && g.FirstMono == time.Duration(r.Mono) && g.LastMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("classified selection gap missing")
}
