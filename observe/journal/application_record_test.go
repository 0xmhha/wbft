package journal

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func applicationFixture() *ApplicationRec {
	return &ApplicationRec{Version: ApplicationSourceVersion, Source: app.FinalizeSource{Run: "original", Engine: 1, Step: 2, Output: 3, Task: 1<<53 + 1}, Arguments: []byte{0xc0}, Result: "ok", EntryMono: 4, Mono: 7, EntryWallNs: ^uint64(0), WallNs: ^uint64(0)}
}
func TestApplicationRecordStrictBoundariesAndDomains(t *testing.T) {
	r := applicationFixture()
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	row, err := decodeBody(KindApplication, raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeBody(row, row.JSeq)
	if err != nil || row.JSeq != ^uint64(0) || !bytes.Equal(raw, again) {
		t.Fatal("application bytes changed", err)
	}
	var wire applicationRLP
	if err = rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// Only copied diagnostic metadata is changed; no node or executor runs.
	for _, mutate := range []func(*applicationRLP){
		func(w *applicationRLP) { w.Format++ }, func(w *applicationRLP) { w.Source.Version++ },
		func(w *applicationRLP) { w.Source.Mono = 1 << 63 }, func(w *applicationRLP) { w.Source.EntryMono = 8 },
		func(w *applicationRLP) { w.Source.AlreadyHead = 2 }, func(w *applicationRLP) { w.Source.Result = "unknown" },
		func(w *applicationRLP) { w.Source.Source.Run = "" }, func(w *applicationRLP) { w.Source.Source.Task = 0 },
		func(w *applicationRLP) { w.Source.Arguments = nil }, func(w *applicationRLP) { w.Source.Unavailable = "unknown" },
	} {
		copy := wire
		mutate(&copy)
		changed, err := rlp.Encode(&copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeBody(KindApplication, changed); err == nil {
			t.Fatal("invalid application source accepted", copy)
		}
	}
}
func TestApplicationRecordCopyBudgetAndClassifiedGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/application-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	r := applicationFixture()
	if size(Record{Body: r}) < 384+int64(len(r.Arguments)) || monoOf(Record{Body: r}) != 7 {
		t.Fatal("application bypassed accounting")
	}
	w.Put(Record{Body: r})
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := ReadAll(fs, "/application-gap")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if g, ok := row.Body.(*GapRec); ok {
			for _, k := range g.ByKind {
				if k.Kind == uint64(KindApplication) && k.Count == 1 && g.FirstMono == 7 && g.LastMono == 7 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("application drop lost its domain")
	}
}
func TestApplicationProviderMissingDoesNotClaimExecution(t *testing.T) {
	check, err := CheckApplicationSources(context.Background(), nil, nil, nil, ApplicationLimits{})
	if err != nil || check.Status != "unavailable" || check.Reason != "provider_missing" || check.PhysicalStatus != "unavailable" {
		t.Fatal(check, err)
	}
}
