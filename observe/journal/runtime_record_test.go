package journal

import (
	"bytes"
	"testing"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func runtimeFixture() *RuntimeRec {
	return &RuntimeRec{Version: RuntimeSourceVersion, Sequence: 1<<53 + 3, Request: 1<<53 + 1, Namespace: "original", Component: RuntimeWriter, Phase: "return", SessionRun: "original", Session: 1<<53 + 1, Result: "returned", Mono: 7, WallNs: ^uint64(0)}
}

func TestRuntimeRecordStrictOriginalBoundaryIdentity(t *testing.T) {
	source := runtimeFixture()
	raw, err := encodeBody(Record{Body: source}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	row, err := decodeBody(KindRuntime, raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeBody(row, row.JSeq)
	if err != nil || row.JSeq != ^uint64(0) || !bytes.Equal(raw, again) {
		t.Fatal("runtime identity changed", err)
	}
	var wire runtimeRLP
	if err = rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// These changes are detached wire metadata. No original actor runs.
	for _, change := range []func(*runtimeRLP){
		func(w *runtimeRLP) { w.Format++ }, func(w *runtimeRLP) { w.Source.Version++ },
		func(w *runtimeRLP) { w.Source.Namespace = "" }, func(w *runtimeRLP) { w.Source.Sequence = 0 },
		func(w *runtimeRLP) { w.Source.Request = w.Source.Sequence }, func(w *runtimeRLP) { w.Source.Request = 0 },
		func(w *runtimeRLP) { w.Source.Component = "unknown" }, func(w *runtimeRLP) { w.Source.Phase = "unknown" },
		func(w *runtimeRLP) { w.Source.SessionRun = "changed" }, func(w *runtimeRLP) { w.Source.Session = 0 },
		func(w *runtimeRLP) { w.Source.Result = "ok" }, func(w *runtimeRLP) { w.Source.Mono = 1 << 63 },
		func(w *runtimeRLP) { w.Source.Unavailable = "unknown" },
	} {
		copied := wire
		change(&copied)
		changed, e := rlp.Encode(&copied)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = decodeBody(KindRuntime, changed); e == nil {
			t.Fatal("invalid runtime metadata accepted", copied)
		}
	}
}

func TestRuntimeRecordBudgetKeepsClassifiedLoss(t *testing.T) {
	fs := fsys.NewMem()
	writer, err := Open(Options{FS: fs, Dir: "/runtime-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	source := runtimeFixture()
	if size(Record{Body: source}) < 320 || monoOf(Record{Body: source}) != 7 {
		t.Fatal("runtime source bypassed accounting")
	}
	writer.Put(Record{Body: source})
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := ReadAll(fs, "/runtime-gap")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if gap, ok := row.Body.(*GapRec); ok {
			for _, kind := range gap.ByKind {
				if kind.Kind == uint64(KindRuntime) && kind.Count == 1 && gap.FirstMono == 7 && gap.LastMono == 7 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("lost runtime source was not classified")
	}
}
