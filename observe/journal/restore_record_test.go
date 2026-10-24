package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
)

func restoreRecordFixture() *RestoreRec {
	return &RestoreRec{Version: RestoreSourceVersion, EngineRun: 1, Read: WALReadRef{"normal-reader", 1, 2}, From: "10", Installed: 1, Steps: 1, Generations: make([]uint64, 4), Mono: 23, WallNs: ^uint64(0)}
}
func TestRestoreRecordStrictSeparateVersion(t *testing.T) {
	r := restoreRecordFixture()
	r.EngineRun = 1<<53 + 1
	raw, err := encodeBody(Record{Body: r}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeBody(KindRestore, raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeBody(back, back.JSeq)
	if err != nil || back.JSeq != ^uint64(0) || !bytes.Equal(raw, again) {
		t.Fatal("restore source changed", err)
	}
	for _, mode := range []string{"format", "version", "owner", "namespace", "height", "flag", "generations", "time", "unavailable", "duplicate_input", "attempt_shape"} {
		t.Run(mode, func(t *testing.T) {
			var w restoreRLP
			if err := rlp.DecodeStrict(raw, &w); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "format":
				w.Format++
			case "version":
				w.Source.Version++
			case "owner":
				w.Source.EngineRun = 0
			case "namespace":
				w.Source.Read.Namespace = ""
			case "height":
				w.Source.From = "010"
			case "flag":
				w.Source.Installed = 2
			case "generations":
				w.Source.Generations = nil
			case "time":
				w.Source.Mono = 1 << 63
			case "unavailable":
				w.Source.Unavailable = "unknown"
			case "duplicate_input":
				w.Source.Inputs = []uint64{2, 2}
			case "attempt_shape":
				w.Source.Attempts = []RestoreAttempt{{}}
			}
			b, err := rlp.Encode(&w)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeBody(KindRestore, b); err == nil {
				t.Fatal("contradictory metadata accepted", mode)
			}
		})
	}
}
func TestRestoreRecordClassifiedQueueGap(t *testing.T) {
	r := restoreRecordFixture()
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/restore-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	if size(Record{Body: r}) < 512 || monoOf(Record{Body: r}) != time.Duration(r.Mono) {
		t.Fatal("restore accounting missing")
	}
	w.Put(Record{Body: r})
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/restore-gap")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if gap, ok := rec.Body.(*GapRec); ok {
			for _, k := range gap.ByKind {
				if k.Kind == uint64(KindRestore) && k.Count == 1 && gap.FirstMono == time.Duration(r.Mono) {
					return
				}
			}
		}
	}
	t.Fatal("restore gap not classified")
}
