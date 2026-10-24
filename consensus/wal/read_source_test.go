package wal

import (
	"bytes"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
)

func TestReadSourceNormalFramesFrozenNamespaceAndDetachedCopy(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/read-source", Options{SegmentBytes: 80})
	originals := []Record{rec(11), rec(12), rec(13), rec(14)}
	for _, r := range originals {
		if _, err := l.AppendSync(r); err != nil {
			t.Fatal(err)
		}
	}
	plain, positions, err := ReadAll(fs, "/read-source")
	if err != nil {
		t.Fatal(err)
	}
	records, actual, source, err := l.ReadAllObserved("original-reader", ReadSourceLimits{Frames: 32, Bytes: 4096})
	if err != nil || source.Unavailable != "" || source.Error != "" || source.Log == 0 || source.Sequence != 1 || source.Namespace != "original-reader" || !equalRecords(plain, records) || !slices.Equal(positions, actual) || len(source.Frames) != len(plain) {
		t.Fatal("original read changed", source, err)
	}
	for i, f := range source.Frames {
		encoded, e := Encode(plain[i])
		if e != nil || f.Position != positions[i] || !bytes.Equal(f.Bytes, encoded) {
			t.Fatal("original frame or position changed", i, e)
		}
	}
	_, _, later, err := l.ReadAllObserved("later-reader", ReadSourceLimits{Frames: 32, Bytes: 4096})
	if err != nil || later.Namespace != source.Namespace || later.Log != source.Log || later.Sequence != 2 {
		t.Fatal("source was rebound", later, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Only detached diagnostic data is changed after the log has closed.
	source.Frames[0].Bytes[0] ^= 1
	records[0].Body[0] ^= 1
	unchanged, _, err := ReadAll(fs, "/read-source")
	if err != nil || !equalRecords(unchanged, plain) || !bytes.Equal(later.Frames[0].Bytes, mustReadFrame(t, plain[0])) {
		t.Fatal("diagnostics changed original bytes", err)
	}
	reopened, _ := mustOpen(t, fs, "/read-source", Options{})
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, _, next, err := reopened.ReadAllObserved("new-reader", ReadSourceLimits{Frames: 32, Bytes: 4096})
	if err != nil || next.Log == source.Log || next.Sequence != 1 || next.Namespace != "new-reader" {
		t.Fatal("a new log lifetime reused an old read source", next, err)
	}
}
func mustReadFrame(t *testing.T, r Record) []byte {
	t.Helper()
	b, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadSourceBoundsPreserveOriginalResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits ReadSourceLimits
		reason string
	}{{"limits", ReadSourceLimits{}, "inspection_limits_required"}, {"frames", ReadSourceLimits{Frames: 1, Bytes: 4096}, "frame_limit"}, {"bytes", ReadSourceLimits{Frames: 32, Bytes: 1}, "byte_limit"}} {
		t.Run(tc.name, func(t *testing.T) {
			fs := fsys.NewMem()
			l, _ := mustOpen(t, fs, "/bounds", Options{})
			for _, r := range []Record{rec(11), rec(12)} {
				if _, err := l.AppendSync(r); err != nil {
					t.Fatal(err)
				}
			}
			plain, positions, err := ReadAll(fs, "/bounds")
			if err != nil {
				t.Fatal(err)
			}
			records, actual, source, err := l.ReadAllObserved("bounded-reader", tc.limits)
			if err != nil || !equalRecords(plain, records) || !slices.Equal(positions, actual) || source.Unavailable != tc.reason || len(source.Frames) != 0 {
				t.Fatal("diagnostic limit changed functional reading", source, err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestReadSourceMissingNamespaceNeverRebinds(t *testing.T) {
	fs := fsys.NewMem()
	l, _ := mustOpen(t, fs, "/unqualified", Options{})
	limits := ReadSourceLimits{Frames: 1, Bytes: 128}
	_, _, first, err := l.ReadAllObserved("", limits)
	if err != nil || first.Unavailable != "namespace_missing" {
		t.Fatal(first, err)
	}
	_, _, second, err := l.ReadAllObserved("later", limits)
	if err != nil || second.Namespace != "" || second.Log != first.Log || second.Sequence != 2 || second.Unavailable != "namespace_missing" {
		t.Fatal("late namespace qualified an earlier reader", second, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
