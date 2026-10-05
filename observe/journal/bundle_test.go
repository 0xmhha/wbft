package journal

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// bundleJournal writes two writer runs in small segments: run-1 with heads
// 0..9 and run-2 with heads 10..19 (step i reads head i/10, 10 steps per
// head).
func bundleJournal(t *testing.T, fs fsys.FS) {
	t.Helper()
	for r, run := range []string{"run-1", "run-2"} {
		id := ident()
		id.Run = run
		w, err := Open(Options{FS: fs, Dir: "/j", SegmentBytes: 2048, Synchronous: true}, id)
		if err != nil {
			t.Fatal(err)
		}
		for i := uint64(0); i < 100; i++ {
			s := step(uint64(r)*100 + i)
			w.NoteHead(s.HeadNumber)
			w.Put(Record{Body: s})
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func h(n uint64) *types.Height { x := types.HeightFromUint64(n); return &x }

// TestBundleRoundTrip bundles the whole journal and reads it back: the
// records are those of the journal, and the manifest names both runs and
// every file with its hash.
func TestBundleRoundTrip(t *testing.T) {
	fs := fsys.NewMem()
	bundleJournal(t, fs)
	var buf bytes.Buffer
	m, err := WriteBundle(fs, "/j", &buf, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.StartsAtRunStart || fmt.Sprint(m.Runs) != "[run-1 run-2]" || m.Heights.FirstHead != "0" || m.Heights.LastHead != "19" ||
		m.Node.Mode != "standalone" || m.Node.ChainID != "8282" || len(m.Files) == 0 {
		t.Fatalf("manifest %+v", m)
	}
	got, err := ReadBundle(bytes.NewReader(buf.Bytes()), fs, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != len(m.Files) {
		t.Fatalf("read manifest %+v", got)
	}
	a, err := ReadAll(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadAll(fs, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(a) == 0 {
		t.Fatalf("bundle holds %d records, the journal %d", len(b), len(a))
	}
}

// TestBundleRange keeps the segments that decide heights From..To and the
// warm-up heights before them, as one run of segments.
func TestBundleRange(t *testing.T) {
	fs := fsys.NewMem()
	bundleJournal(t, fs)
	var buf bytes.Buffer
	// Heights 15..16 read heads 14..15; with two warm-up heights, heads
	// from 12.
	m, err := WriteBundle(fs, "/j", &buf, BundleOptions{From: h(15), To: h(16), Warmup: 2})
	if err != nil {
		t.Fatal(err)
	}
	if m.StartsAtRunStart || fmt.Sprint(m.Runs) != "[run-2]" || m.Heights.From != "15" || m.Heights.To != "16" {
		t.Fatalf("manifest %+v", m)
	}
	first, _ := strconv.Atoi(m.Heights.FirstHead)
	last, _ := strconv.Atoi(m.Heights.LastHead)
	if first > 12 || first < 10 || last < 15 || last > 17 {
		t.Fatalf("heads %d..%d, want a cover of 12..15 from the second run", first, last)
	}
	// A range in the first run starts at its start.
	m, err = WriteBundle(fs, "/j", io.Discard, BundleOptions{To: h(3)})
	if err != nil || !m.StartsAtRunStart || fmt.Sprint(m.Runs) != "[run-1]" {
		t.Fatalf("first-run manifest %+v %v", m, err)
	}
	if _, err := WriteBundle(fs, "/j", io.Discard, BundleOptions{From: h(500)}); err == nil {
		t.Fatal("a range past the journal was bundled")
	}
}

// TestReadBundleRefuses a changed file, an entry the manifest does not
// list, a path outside the destination and a missing file.
func TestReadBundleRefuses(t *testing.T) {
	fs := fsys.NewMem()
	bundleJournal(t, fs)
	var buf bytes.Buffer
	if _, err := WriteBundle(fs, "/j", &buf, BundleOptions{}); err != nil {
		t.Fatal(err)
	}
	// rewrite copies the bundle through f, which may change an entry.
	rewrite := func(f func(h *tar.Header, b []byte) (*tar.Header, []byte)) []byte {
		var out bytes.Buffer
		tr, tw := tar.NewReader(bytes.NewReader(buf.Bytes())), tar.NewWriter(&out)
		for {
			hd, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(tr)
			if hd, b = f(hd, b); hd == nil {
				continue
			}
			hd.Size = int64(len(b))
			if err := tw.WriteHeader(hd); err != nil {
				t.Fatal(err)
			}
			_, _ = tw.Write(b)
		}
		_ = tw.Close()
		return out.Bytes()
	}
	segName := ""
	segs, _ := wal.Segments(fs, "/j")
	segName = segs[0].Name
	for _, tc := range []struct {
		name string
		edit func(h *tar.Header, b []byte) (*tar.Header, []byte)
		want string
	}{
		{"changed file", func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == segName {
				b = append([]byte(nil), b...)
				b[len(b)/2] ^= 1
			}
			return h, b
		}, "does not match its hash"},
		{"unlisted entry", func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == segName {
				h.Name = "99999999999999999999.wal"
			}
			return h, b
		}, "unexpected entry"},
		{"path outside", func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == segName {
				h.Name = "../" + segName
			}
			return h, b
		}, "unexpected entry"},
		{"missing file", func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == segName {
				return nil, nil
			}
			return h, b
		}, "is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadBundle(bytes.NewReader(rewrite(tc.edit)), fs, "/y-"+strings.ReplaceAll(tc.name, " ", "-"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}
