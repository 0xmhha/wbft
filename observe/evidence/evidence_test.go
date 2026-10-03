package evidence

import (
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
)

// TestStore adds evidence across rotations and checks the range lookup,
// the removal of old rotated files, a torn last line and the numbering
// after a reopen.
func TestStore(t *testing.T) {
	f := fsys.NewMem()
	now := time.Unix(1_700_000_000, 0)
	o := Options{MaxFileBytes: 300, MaxAge: time.Hour, Now: func() time.Time { return now }}
	s, err := Open(f, "/ev", o)
	if err != nil {
		t.Fatal(err)
	}
	add := func(h int64) {
		t.Helper()
		if err := s.Add(Record{Height: big.NewInt(h).String(), Round: "0", Code: 2, Kind: "equivocation", Time: now}); err != nil {
			t.Fatal(err)
		}
	}
	for h := int64(1); h <= 6; h++ {
		add(h)
	}
	names, err := s.rotated()
	if err != nil || len(names) == 0 {
		t.Fatalf("no rotation: %v %v", names, err)
	}
	got, err := s.Range(big.NewInt(2), big.NewInt(4))
	if err != nil || len(got) != 3 || got[0].Height != "2" || got[2].Height != "4" {
		t.Fatalf("range 2..4: %+v %v", got, err)
	}
	// A torn last line (a crash during a write) is skipped.
	w, err := f.OpenFile(path.Join("/ev", current), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{"height":"9"`))
	_ = w.Close()
	if got, err := s.Range(big.NewInt(1), big.NewInt(9)); err != nil || len(got) != 6 {
		t.Fatalf("with a torn line: %d %v", len(got), err)
	}
	// Two hours later a reopen removes the rotated files (their records
	// are older than an hour) and goes on numbering after them.
	before := s.next
	now = now.Add(2 * time.Hour)
	s, err = Open(f, "/ev", o)
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := s.rotated(); len(names) != 0 {
		t.Fatalf("old rotated files kept: %v", names)
	}
	if s.next != before {
		t.Fatalf("next rotated file %d, want %d", s.next, before)
	}
}
