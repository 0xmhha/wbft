package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestAppQueueRecordStrictCodecAndOriginalIdentity(t *testing.T) {
	input, err := inputlog.Encode(consensus.PeerConnected{Addr: types.Address{3}})
	if err != nil {
		t.Fatal(err)
	}
	r := &AppQueueRec{Version: AppQueueSourceVersion, Sequence: 1<<53 + 1, Request: 1<<53 + 1, Action: "append", InputKind: inputlog.KindPeerConnected, Input: input, Before: 5, After: 6, Mono: 23, WallNs: -1}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindAppQueue, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*AppQueueRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Request != r.Request || back.WallNs != -1 || !bytes.Equal(back.Input, input) {
		t.Fatal("original identity, bytes or integer precision changed", back)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("durable source bytes changed", err)
	}
	var wire appQueueRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// These are copied offline codec records, not live application inputs.
	for _, change := range []func(*appQueueRLP){
		func(w *appQueueRLP) { w.Version++ },
		func(w *appQueueRLP) { w.Sequence = 0 },
		func(w *appQueueRLP) { w.Request++ },
		func(w *appQueueRLP) { w.After++ },
		func(w *appQueueRLP) { w.InputKind = inputlog.KindTimeout },
		func(w *appQueueRLP) { w.Action = "unknown" },
		func(w *appQueueRLP) { w.Mono = 1 << 63 },
	} {
		w := wire
		change(&w)
		body, err := rlp.Encode(&w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindAppQueue, body); err == nil {
			t.Fatal("invalid application queue source accepted")
		}
	}
}

func TestAppQueueRecordQueueBudgetAndKindGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/app-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	input, err := inputlog.Encode(consensus.PeerConnected{Addr: types.Address{3}})
	if err != nil {
		t.Fatal(err)
	}
	r := &AppQueueRec{Version: AppQueueSourceVersion, Sequence: 1, Request: 1, Action: "append", InputKind: inputlog.KindPeerConnected, Input: input, After: 1, Mono: 23 * time.Second}
	if monoOf(Record{Body: r}) != r.Mono || size(Record{Body: r}) < 256+int64(len(input)) {
		t.Fatal("application queue source missing from byte/clock accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/app-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindAppQueue) && kind.Count == 1 && gap.FirstMono == r.Mono && gap.LastMono == r.Mono {
					return
				}
			}
		}
	}
	t.Fatal("bounded writer did not retain the application queue source gap")
}
