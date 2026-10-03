package rejection

import (
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
)

// TestStore keeps between half and all of the record limit, most recent
// last, finds records by block number and goes on counting after a
// reopen.
func TestStore(t *testing.T) {
	f := fsys.NewMem()
	s, err := Open(f, "/rej", Options{MaxRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	add := func(s *Store, n int64) {
		t.Helper()
		if err := s.Add(Record{Number: big.NewInt(n).String(), Step: "P3", Class: "ErrInvalidProposal", Path: "preprepare"}); err != nil {
			t.Fatal(err)
		}
	}
	for n := int64(1); n <= 5; n++ { // 1, 2 | 3, 4 | 5: the first file is gone
		add(s, n)
	}
	all, err := s.Range(big.NewInt(0), big.NewInt(100))
	if err != nil || len(all) != 3 || all[0].Number != "3" || all[2].Number != "5" || all[0].Step != "P3" {
		t.Fatalf("kept %+v %v", all, err)
	}
	if got, _ := s.Range(big.NewInt(4), big.NewInt(4)); len(got) != 1 || got[0].Number != "4" {
		t.Fatalf("range 4..4: %+v", got)
	}
	// A reopen counts the current file (5) and rotates after one more.
	s, err = Open(f, "/rej", Options{MaxRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	add(s, 6)
	add(s, 7) // rotates: 5, 6 | 7
	if all, _ := s.Range(big.NewInt(0), big.NewInt(100)); len(all) != 3 || all[0].Number != "5" || all[2].Number != "7" {
		t.Fatalf("after a reopen %+v", all)
	}
}
