package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// writeJournal writes two writer runs into /j on fs, each over heights
// from..to with a step and a sent message per height, in small segments.
func writeJournal(t *testing.T, fs fsys.FS) {
	t.Helper()
	for i, run := range []string{"run-a", "run-b"} {
		jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", SegmentBytes: 600, Synchronous: true},
			journal.Identity{Self: types.Address{1}, Run: run, Mode: "standalone", Commit: "test"})
		if err != nil {
			t.Fatal(err)
		}
		jw.SetEngineRun(1)
		for h := uint64(1); h <= 10; h++ {
			height := types.HeightFromUint64(uint64(i)*10 + h)
			jw.NoteHead(height)
			jw.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: h, InputKind: "timer", Input: []byte{1}, Via: "timer",
				HeadNumber: height}})
			p := []byte{byte(h), 0xc0}
			jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, PeerIdx: 1, Mono: time.Second, WallNs: 1, Code: 0x12,
				WireCode: 0x22, Payload: p, DedupKey: codec.DedupKey(p), Write: "ok"}})
		}
		if err := jw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func runJSON(t *testing.T, fs fsys.FS, want int, out any, args ...string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(args, fs, &stdout, &stderr); code != want {
		t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, stdout.String(), stderr.String())
	}
	if out != nil {
		if err := json.Unmarshal(stdout.Bytes(), out); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stdout.String())
		}
	}
}

// TestStat reports the segments, the record counts, the writer runs and
// the head range of the steps.
func TestStat(t *testing.T) {
	fs := fsys.NewMem()
	writeJournal(t, fs)
	var st statResult
	runJSON(t, fs, 0, &st, "stat", "--dir", "/j")
	if len(st.Segments) < 4 || st.End != "eof" || st.Records["step"] != 20 || st.Records["msg"] != 20 || st.Records["segment"] != int64(len(st.Segments)) {
		t.Fatalf("stat %+v", st)
	}
	if len(st.Runs) != 2 || st.Runs[0].Run != "run-a" || st.Runs[1].Run != "run-b" || len(st.Runs[1].EngineRuns) != 1 {
		t.Fatalf("runs %+v", st.Runs)
	}
	first, last := st.Segments[0], st.Segments[len(st.Segments)-1]
	if first.MinHead != "1" || last.MaxHead != "20" || first.FirstJSeq != 1 || !first.Closed {
		t.Fatalf("segments %+v %+v", first, last)
	}
}

// TestVerify accepts a whole journal and reports damage, a record that
// does not follow its predecessor and a wrong dedup key.
func TestVerify(t *testing.T) {
	fs := fsys.NewMem()
	writeJournal(t, fs)
	var v verifyResult
	runJSON(t, fs, 0, &v, "verify", "--dir", "/j")
	if len(v.Problems) != 0 || v.Records == 0 {
		t.Fatalf("verify %+v", v)
	}

	// A wrong dedup key in a third run.
	jw, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Run: "run-c"})
	if err != nil {
		t.Fatal(err)
	}
	jw.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: 0x12, WireCode: 0x12, Payload: []byte{1}, Offer: "queued"}})
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 1, &v, "verify", "--dir", "/j")
	if len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "dedup key") {
		t.Fatalf("problems %q", v.Problems)
	}

	// A damaged frame in the second segment stops the reading.
	segs, err := wal.Segments(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Corrupt("/j/"+segs[1].Name, func(b []byte) []byte { b[len(b)/2] ^= 0xff; return b }); err != nil {
		t.Fatal(err)
	}
	runJSON(t, fs, 1, &v, "verify", "--dir", "/j")
	if !strings.Contains(strings.Join(v.Problems, "\n"), "reading stopped") {
		t.Fatalf("problems %q", v.Problems)
	}
}

// TestVerifyMissingSegment reports the break in the record numbers that a
// lost middle segment leaves.
func TestVerifyMissingSegment(t *testing.T) {
	fs := fsys.NewMem()
	writeJournal(t, fs)
	segs, err := wal.Segments(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.RemoveSegment(fs, "/j", segs[2].Index); err != nil {
		t.Fatal(err)
	}
	var v verifyResult
	runJSON(t, fs, 1, &v, "verify", "--dir", "/j")
	if len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "jseq") {
		t.Fatalf("problems %q", v.Problems)
	}
}

// TestPrune removes the segments below head - keep-heights, keeps the last
// segment, and leaves a journal that verifies from its first remaining
// record.
func TestPrune(t *testing.T) {
	fs := fsys.NewMem()
	writeJournal(t, fs)
	var before statResult
	runJSON(t, fs, 0, &before, "stat", "--dir", "/j")
	var p pruneResult
	runJSON(t, fs, 0, &p, "prune", "--dir", "/j", "--keep-heights", "5", "--max-bytes", "0")
	if p.Head != "20" || len(p.Removed) == 0 || len(p.Removed) >= len(before.Segments) {
		t.Fatalf("prune %+v of %d segments", p, len(before.Segments))
	}
	var after statResult
	runJSON(t, fs, 0, &after, "stat", "--dir", "/j")
	if after.Segments[len(after.Segments)-1].Name != before.Segments[len(before.Segments)-1].Name {
		t.Fatal("the last segment was removed")
	}
	// Pruning reads the head range of each closed segment's index.
	for _, s := range after.Segments[:len(after.Segments)-1] {
		ix, ok := journal.ReadIndex(fs, "/j", s.Name)
		if !ok || ix.MaxHeight == nil {
			continue
		}
		if mh, err := strconv.Atoi(*ix.MaxHeight); err != nil || mh < 15 {
			t.Fatalf("segment below head - 5 kept: %+v %v", s, *ix.MaxHeight)
		}
	}
	var v verifyResult
	runJSON(t, fs, 0, &v, "verify", "--dir", "/j")
	if len(v.Problems) != 0 {
		t.Fatalf("problems after prune %q", v.Problems)
	}
	// --head overrides the index files; a size bound removes the oldest.
	runJSON(t, fs, 0, &p, "prune", "--dir", "/j", "--keep-heights", "0", "--max-bytes", "1", "--head", "20")
	runJSON(t, fs, 0, &after, "stat", "--dir", "/j")
	if len(after.Segments) != 1 {
		t.Fatalf("segments after a size prune: %d", len(after.Segments))
	}
}

// TestUsage refuses a missing directory and an unknown command.
func TestUsage(t *testing.T) {
	fs := fsys.NewMem()
	runJSON(t, fs, 2, nil, "stat")
	runJSON(t, fs, 2, nil, "export", "--dir", "/j")
	runJSON(t, fs, 2, nil, "prune", "--dir", "/j", "--head", "x")
	runJSON(t, fs, 2, nil)
}
