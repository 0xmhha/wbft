package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestInboxRecordStrictRoundTripAndIntegerIdentity(t *testing.T) {
	r := &InboxRec{Version: InboxSourceVersion, Sequence: 1<<53 + 1, Request: 1<<53 + 1, Action: "append", Payload: []byte{1, 2}, After: 1, BytesAfter: 2, Mono: 23, WallNs: ^uint64(0)}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindInbox, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*InboxRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Request != r.Request || back.WallNs != r.WallNs || !bytes.Equal(back.Payload, r.Payload) {
		t.Fatal("durable source identity changed", decoded)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("durable bytes changed", err)
	}
	var wire inboxRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*inboxRLP){
		func(w *inboxRLP) { w.Format++ }, func(w *inboxRLP) { w.Source.Version++ }, func(w *inboxRLP) { w.Source.Sequence = 0 }, func(w *inboxRLP) { w.Source.Request++ }, func(w *inboxRLP) { w.Source.Mono = 1 << 63 }, func(w *inboxRLP) { w.Source.RecvMono = 1 << 63 }, func(w *inboxRLP) { w.Source.Action = "unknown" }, func(w *inboxRLP) { w.Source.Manual = 2 }, func(w *inboxRLP) { w.Source.SnapshotReplayed = 2 }, func(w *inboxRLP) { w.Source.Unavailable = "unknown" }, func(w *inboxRLP) { w.Source.SnapshotPhase = "start" },
	} {
		copied := wire
		change(&copied)
		body, err := rlp.Encode(&copied)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindInbox, body); err == nil {
			t.Fatal("invalid copied metadata accepted", copied)
		}
	}
}

func TestInboxRecordByteBudgetAndClassifiedGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/inbox-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	r := &InboxRec{Version: InboxSourceVersion, Sequence: 1, Request: 1, Action: "append", Payload: []byte{1, 2}, After: 1, BytesAfter: 2, Mono: uint64(23 * time.Second)}
	if monoOf(Record{Body: r}) != time.Duration(r.Mono) || size(Record{Body: r}) < 768+int64(len(r.Payload)) {
		t.Fatal("source bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/inbox-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindInbox) && kind.Count == 1 && gap.FirstMono == time.Duration(r.Mono) && gap.LastMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("classified inbox gap missing")
}
