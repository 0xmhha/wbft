package journal

import (
	"bytes"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"testing"
	"time"
)

func TestReceiveDispatchRecordStrictDurableIdentity(t *testing.T) {
	input, err := inputlog.Encode(consensus.Message{})
	if err != nil {
		t.Fatal(err)
	}
	r := &ReceiveDispatchRec{Version: ReceiveDispatchSourceVersion, Sequence: 1<<53 + 1, Request: 1<<53 + 1, EngineRun: 1, BeforeStep: 1, Action: "prepare", Via: "peer", Source: transport.ReceivePreparationSource{WriterRun: "original-writer", Ledger: 1, Sequence: 3}, Scope: 2, Decision: uint64(transport.ReceiveReserved), Selection: 4, InboxRequest: 5, InputKind: inputlog.KindMessage, Input: input, Mono: 6, WallNs: ^uint64(0)}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindReceiveDispatch, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*ReceiveDispatchRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Request != r.Request || back.Source != r.Source || back.WallNs != r.WallNs || !bytes.Equal(back.Input, r.Input) {
		t.Fatal("durable preparation source changed", decoded)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("durable bytes changed", err)
	}
	var wire receiveDispatchRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*receiveDispatchRLP){func(w *receiveDispatchRLP) { w.Format++ }, func(w *receiveDispatchRLP) { w.Source.Version++ }, func(w *receiveDispatchRLP) { w.Source.Request++ }, func(w *receiveDispatchRLP) { w.Source.Sequence = 0 }, func(w *receiveDispatchRLP) { w.Source.Mono = 1 << 63 }, func(w *receiveDispatchRLP) { w.Source.Action = "unknown" }, func(w *receiveDispatchRLP) { w.Source.Decision = uint64(transport.ReceiveRegistered) }, func(w *receiveDispatchRLP) { w.Source.Unavailable = "unknown" }, func(w *receiveDispatchRLP) { w.Source.Source.Sequence = 0 }} {
		c := wire
		alter(&c)
		body, e := rlp.Encode(&c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := decodeBody(KindReceiveDispatch, body); e == nil {
			t.Fatal("invalid metadata accepted", c)
		}
	}
}

func TestReceiveDispatchRecordBudgetClassifiesGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/receive-dispatch-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	input, err := inputlog.Encode(consensus.Message{})
	if err != nil {
		t.Fatal(err)
	}
	r := &ReceiveDispatchRec{Version: ReceiveDispatchSourceVersion, Sequence: 1, Request: 1, EngineRun: 1, BeforeStep: 1, Action: "prepare", Via: "peer", Source: transport.ReceivePreparationSource{WriterRun: "original-writer", Ledger: 1, Sequence: 1}, Scope: 1, Decision: uint64(transport.ReceiveReserved), Selection: 1, InboxRequest: 1, InputKind: inputlog.KindMessage, Input: input, Mono: uint64(23 * time.Second)}
	if monoOf(Record{Body: r}) != time.Duration(r.Mono) || size(Record{Body: r}) < 512 {
		t.Fatal("receive disposition bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/receive-dispatch-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if g, ok := record.Body.(*GapRec); ok {
			for _, k := range g.ByKind {
				if k.Kind == uint64(KindReceiveDispatch) && k.Count == 1 && g.FirstMono == time.Duration(r.Mono) && g.LastMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("classified receive disposition gap missing")
}
