package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestInternalRecordStrictIdentityAndWire(t *testing.T) {
	input, err := inputlog.Encode(consensus.BroadcastFailed{})
	if err != nil {
		t.Fatal(err)
	}
	r := &InternalRec{Version: InternalSourceVersion, Sequence: 1<<53 + 1, Request: 1<<53 + 1, EngineRun: 1, Step: 2, Output: 3, Action: "append", Origin: "signer_missing", InputKind: inputlog.KindBroadcastFailed, Input: input, After: 1, Unavailable: "signer_state", Mono: 5, WallNs: ^uint64(0)}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindInternal, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*InternalRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Request != r.Request || back.WallNs != r.WallNs || !bytes.Equal(back.Input, r.Input) {
		t.Fatal("identity lost", decoded)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("wire changed", err)
	}
	var wire internalRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*internalRLP){func(w *internalRLP) { w.Format++ }, func(w *internalRLP) { w.Source.Version++ }, func(w *internalRLP) { w.Source.Sequence = 0 }, func(w *internalRLP) { w.Source.Request++ }, func(w *internalRLP) { w.Source.Action = "unknown" }, func(w *internalRLP) { w.Source.Origin = "unknown" }, func(w *internalRLP) { w.Source.Output = 0 }, func(w *internalRLP) { w.Source.Mono = 1 << 63 }, func(w *internalRLP) { w.Source.Unavailable = "unknown" }} {
		c := wire
		alter(&c)
		body, e := rlp.Encode(&c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := decodeBody(KindInternal, body); e == nil {
			t.Fatal("invalid metadata accepted", c)
		}
	}
}

func TestInternalRecordBudgetClassifiesGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/internal-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	r := &InternalRec{Version: InternalSourceVersion, Sequence: 1, EngineRun: 1, Action: "reset", Mono: uint64(23 * time.Second)}
	if monoOf(Record{Body: r}) != time.Duration(r.Mono) || size(Record{Body: r}) < 256 {
		t.Fatal("source bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/internal-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if g, ok := record.Body.(*GapRec); ok {
			for _, k := range g.ByKind {
				if k.Kind == uint64(KindInternal) && k.Count == 1 && g.FirstMono == time.Duration(r.Mono) && g.LastMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("classified internal gap missing")
}
