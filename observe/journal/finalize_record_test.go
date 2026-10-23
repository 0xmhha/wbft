package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestFinalizeRecordStrictCodecAndIntegerIdentity(t *testing.T) {
	r := &FinalizeRec{Version: FinalizeSourceVersion, Sequence: 1<<53 + 1, Task: 7, EngineRun: 3, Step: 9, Output: 4, Action: "notify", Input: []byte{1, 2}, QueueRun: "original", QueueRequest: 1<<53 + 4, HasError: true, Mono: 23, WallNs: -1}
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindFinalize, raw)
	if err != nil {
		t.Fatal(err)
	}
	back := decoded.Body.(*FinalizeRec)
	if decoded.JSeq != ^uint64(0) || back.Sequence != r.Sequence || back.Task != r.Task || back.QueueRequest != r.QueueRequest || back.WallNs != -1 || !back.HasError || !bytes.Equal(back.Input, r.Input) {
		t.Fatal("source identity lost", back)
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("durable bytes changed", err)
	}
	var original finalizeRLP
	if err := rlp.DecodeStrict(raw, &original); err != nil {
		t.Fatal(err)
	}
	// Contradictions affect copied codec metadata only, never a running node.
	for _, change := range []func(*finalizeRLP){
		func(w *finalizeRLP) { w.Version++ }, func(w *finalizeRLP) { w.Sequence = 0 }, func(w *finalizeRLP) { w.Task = 0 }, func(w *finalizeRLP) { w.QueueRequest = 0 }, func(w *finalizeRLP) { w.QueueRun = "" }, func(w *finalizeRLP) { w.Action = "unknown" }, func(w *finalizeRLP) { w.HasError = 2 }, func(w *finalizeRLP) { w.Mono = 1 << 63 }, func(w *finalizeRLP) { w.Arguments = []byte{3} }, func(w *finalizeRLP) { w.Unavailable = "unknown" },
	} {
		changed := original
		change(&changed)
		body, err := rlp.Encode(&changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindFinalize, body); err == nil {
			t.Fatal("invalid source accepted", changed)
		}
	}
}

func TestFinalizeRecordByteBudgetAndClassifiedGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/finalize-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	r := &FinalizeRec{Version: FinalizeSourceVersion, Sequence: 1, Task: 1, EngineRun: 1, Step: 1, Output: 1, Action: "enqueue", After: 1, Arguments: []byte{1, 2}, Mono: 23 * time.Second}
	if monoOf(Record{Body: r}) != r.Mono || size(Record{Body: r}) < 256+int64(len(r.Arguments)) {
		t.Fatal("source bypassed queue accounting")
	}
	w.Put(Record{Body: r})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/finalize-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindFinalize) && kind.Count == 1 && gap.FirstMono == r.Mono && gap.LastMono == r.Mono {
					return
				}
			}
		}
	}
	t.Fatal("missing classified finalization gap")
}
