package wal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
)

func rec(i int) Record {
	return Record{Format: 1, Kind: uint8(i % 7), Body: bytes.Repeat([]byte{byte(i)}, i%50)}
}

func mustOpen(t *testing.T, fs fsys.FS, dir string, opt Options) (*Log, Recovery) {
	t.Helper()
	l, r, err := Open(fs, dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	return l, r
}

func readAll(t *testing.T, fs fsys.FS, dir string) []Record {
	t.Helper()
	recs, _, err := ReadAll(fs, dir)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func equalRecords(a, b []Record) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Format != b[i].Format || a[i].Kind != b[i].Kind || !bytes.Equal(a[i].Body, b[i].Body) {
			return false
		}
	}
	return true
}

func TestFrameRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		r := rec(i)
		b, err := Encode(r)
		if err != nil {
			t.Fatal(err)
		}
		got, n, torn, corrupt := decodeFrame(b)
		if torn || corrupt || n != len(b) || !equalRecords([]Record{got}, []Record{r}) {
			t.Fatalf("record %d: n=%d torn=%v corrupt=%v", i, n, torn, corrupt)
		}
		// Every strict prefix is an incomplete frame, never a record.
		for k := 0; k < len(b); k++ {
			if _, _, torn, corrupt := decodeFrame(b[:k]); !torn && !corrupt {
				t.Fatalf("record %d prefix %d decoded", i, k)
			}
		}
	}
}

func TestAppendReadRotate(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/w", Options{SegmentBytes: 200})
	var want []Record
	var pos []Position
	for i := 0; i < 60; i++ {
		p, err := l.Append(rec(i))
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, rec(i))
		pos = append(pos, p)
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	segs, _ := Segments(fs, "/w")
	if len(segs) < 5 {
		t.Fatalf("expected several segments, got %d", len(segs))
	}
	got, gpos, err := ReadAll(fs, "/w")
	if err != nil {
		t.Fatal(err)
	}
	if !equalRecords(got, want) {
		t.Fatalf("records differ")
	}
	for i := range pos {
		if pos[i] != gpos[i] {
			t.Fatalf("position %d: append %v, read %v", i, pos[i], gpos[i])
		}
	}
	// A reader from a middle position continues through later segments.
	r, err := OpenReader(fs, "/w", pos[30])
	if err != nil {
		t.Fatal(err)
	}
	for i := 30; i < 60; i++ {
		g, _, err := r.Next()
		if err != nil || !equalRecords([]Record{g}, []Record{want[i]}) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	// RemoveBefore keeps the segment being written.
	if err := l.RemoveBefore(1 << 62); err != nil {
		t.Fatal(err)
	}
	segs, _ = Segments(fs, "/w")
	if len(segs) != 1 || segs[0].Index != l.Position().Segment {
		t.Fatalf("after RemoveBefore: %+v", segs)
	}
}

func TestHeaderRecords(t *testing.T) {
	fs := fsys.NewMem()
	n := 0
	hdr := func() []Record { n++; return []Record{{Format: 9, Kind: 9, Body: []byte(fmt.Sprint(n))}} }
	l, _ := mustOpen(t, fs, "/w", Options{SegmentBytes: 100, Header: hdr})
	for i := 0; i < 20; i++ {
		if _, err := l.Append(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	segs, _ := Segments(fs, "/w")
	for _, s := range segs {
		r, err := OpenReader(fs, "/w", Position{Segment: s.Index})
		if err != nil {
			t.Fatal(err)
		}
		first, _, err := r.Next()
		if err != nil || first.Kind != 9 {
			t.Fatalf("segment %d does not start with the header record: %v %v", s.Index, first, err)
		}
	}
}

// A crash loses what was not synced; a torn last frame is cut off by Open
// and the reader returns every synced record.
func TestCrashTornTail(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		fs := fsys.NewMem()
		l, _ := mustOpen(t, fs, "/w", Options{SegmentBytes: 400})
		rng := rand.New(rand.NewPCG(seed, 1))
		var synced []Record
		var all []Record
		for i := 0; i < 40; i++ {
			r := rec(i + int(seed))
			all = append(all, r)
			if rng.IntN(4) == 0 {
				if _, err := l.AppendSync(r); err != nil {
					t.Fatal(err)
				}
				synced = append([]Record(nil), all...)
			} else if _, err := l.Append(r); err != nil {
				t.Fatal(err)
			}
			if rng.IntN(5) == 0 {
				if err := l.Flush(); err != nil {
					t.Fatal(err)
				}
			}
		}
		fs.Crash(rng)
		l2, recov := mustOpen(t, fs, "/w", Options{SegmentBytes: 400})
		got := readAll(t, fs, "/w")
		if len(got) < len(synced) || !equalRecords(got[:len(synced)], synced) || !equalRecords(got, all[:len(got)]) {
			t.Fatalf("seed %d: read %d records, synced %d (recovery %+v)", seed, len(got), len(synced), recov)
		}
		if len(recov.Corrupted) != 0 {
			t.Fatalf("seed %d: a crash is not corruption: %+v", seed, recov)
		}
		// Writing continues after the recovered records.
		if _, err := l2.AppendSync(rec(1000)); err != nil {
			t.Fatal(err)
		}
		got2 := readAll(t, fs, "/w")
		if !equalRecords(got2, append(append([]Record(nil), got...), rec(1000))) {
			t.Fatalf("seed %d: append after recovery", seed)
		}
	}
}

// Cutting the log at any byte leaves the complete records before the cut.
func TestTruncateAnywhere(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/w", Options{})
	var want []Record
	var ends []int64
	for i := 0; i < 30; i++ {
		if _, err := l.Append(rec(i)); err != nil {
			t.Fatal(err)
		}
		want = append(want, rec(i))
		ends = append(ends, l.Position().Offset)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join("/w", segmentName(0))
	full, _ := fs.ReadFile(name)
	for cut := int64(0); cut <= int64(len(full)); cut += 3 {
		c := fsys.NewMem()
		_ = c.MkdirAll("/w", 0o700)
		f, _ := c.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0o600)
		_, _ = f.Write(full[:cut])
		_ = f.Sync()
		_ = c.SyncDir("/w")
		_, recov := mustOpen(t, c, "/w", Options{})
		got := readAll(t, c, "/w")
		n := 0
		for n < len(ends) && ends[n] <= cut {
			n++
		}
		if !equalRecords(got, want[:n]) {
			t.Fatalf("cut %d: %d records, want %d", cut, len(got), n)
		}
		if len(recov.Corrupted) != 0 {
			t.Fatalf("cut %d: %+v", cut, recov)
		}
	}
}

// A checksum error moves the segment and every later one aside; the reader
// stops before the damage and writing starts in a new segment.
func TestCorruptSegmentMovedAside(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/w", Options{SegmentBytes: 150})
	var want []Record
	for i := 0; i < 30; i++ {
		if _, err := l.Append(rec(i)); err != nil {
			t.Fatal(err)
		}
		want = append(want, rec(i))
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	segs, _ := Segments(fs, "/w")
	if len(segs) < 4 {
		t.Fatalf("segments: %d", len(segs))
	}
	victim := segs[1]
	if err := fs.Corrupt(filepath.Join("/w", victim.Name), func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b }); err != nil {
		t.Fatal(err)
	}
	// The reader reports the damage.
	if _, _, err := ReadAll(fs, "/w"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	l2, recov := mustOpen(t, fs, "/w", Options{SegmentBytes: 150})
	if len(recov.Corrupted) != len(segs)-1 || recov.Corrupted[0] != victim.Name {
		t.Fatalf("recovery: %+v", recov)
	}
	names, _ := fs.ReadDir("/w")
	moved := 0
	for _, n := range names {
		if filepath.Ext(n) == corruptedSuffix {
			moved++
		}
	}
	if moved != len(segs)-1 {
		t.Fatalf("moved %d segments", moved)
	}
	got := readAll(t, fs, "/w")
	if len(got) == 0 || len(got) >= len(want) || !equalRecords(got, want[:len(got)]) {
		t.Fatalf("records after repair: %d", len(got))
	}
	if _, err := l2.AppendSync(rec(99)); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, "/w"); !equalRecords(got[len(got)-1:], []Record{rec(99)}) {
		t.Fatal("append after repair")
	}
}

// A disk that acknowledges fsync without writing loses the records; the log
// still opens and reads what survived.
func TestLyingFsync(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/w", Options{})
	for i := 0; i < 5; i++ {
		if _, err := l.AppendSync(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	fs.LieSync = true
	for i := 5; i < 10; i++ {
		if _, err := l.AppendSync(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	fs.Crash(nil)
	fs.LieSync = false
	_, recov := mustOpen(t, fs, "/w", Options{})
	got := readAll(t, fs, "/w")
	var want []Record
	for i := 0; i < 5; i++ {
		want = append(want, rec(i))
	}
	if !equalRecords(got, want) || len(recov.Corrupted) != 0 {
		t.Fatalf("got %d records, recovery %+v", len(got), recov)
	}
}

func TestOSFileSystem(t *testing.T) {
	dir := t.TempDir()
	l, _ := mustOpen(t, fsys.OS{}, dir, Options{SegmentBytes: 128})
	var want []Record
	for i := 0; i < 20; i++ {
		if _, err := l.AppendSync(rec(i)); err != nil {
			t.Fatal(err)
		}
		want = append(want, rec(i))
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	_, recov := mustOpen(t, fsys.OS{}, dir, Options{SegmentBytes: 128})
	if got := readAll(t, fsys.OS{}, dir); !equalRecords(got, want) || recov.Records != 20 {
		t.Fatalf("got %d records, recovery %+v", len(got), recov)
	}
}

func TestClosedAndTooLarge(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/w", Options{})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(rec(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after close: %v", err)
	}
	if _, err := Encode(Record{Body: make([]byte, MaxRecordBytes+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
}

// TestSyncTiming reports every fsync of a segment file with its method and
// the duration between two readings of Options.Now, and none without it.
func TestSyncTiming(t *testing.T) {
	fs := fsys.NewMem()
	var at time.Time
	type synced struct {
		method string
		d      time.Duration
	}
	var got []synced
	opt := Options{SegmentBytes: 256,
		Now:    func() time.Time { at = at.Add(time.Millisecond); return at },
		Synced: func(m string, d time.Duration) { got = append(got, synced{m, d}) }}
	l, _ := mustOpen(t, fs, "wal", opt)
	if _, err := l.AppendSync(rec(1)); err != nil {
		t.Fatal(err)
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	for !l.WouldRotate(rec(40)) {
		if _, err := l.Append(rec(40)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Append(rec(40)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, s := range got {
		if s.d != time.Millisecond {
			t.Fatalf("duration %v of %s", s.d, s.method)
		}
		methods = append(methods, s.method)
	}
	if !slices.Equal(methods, []string{"append_sync", "sync", "rotate", "close"}) {
		t.Fatalf("methods %v", methods)
	}

	got = nil
	l, _ = mustOpen(t, fs, "wal2", Options{Synced: opt.Synced})
	if _, err := l.AppendSync(rec(1)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("timed without Now: %v", got)
	}
}
