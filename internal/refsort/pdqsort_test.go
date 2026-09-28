package refsort

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// fixture is testdata/reference.json, the orders of the reference
// implementation written by testdata/gen (see the comment there).
type fixture struct {
	Toolchain string `json:"toolchain"`
	Cases     []struct {
		Keys []uint64 `json:"keys"`
		Desc []int    `json:"desc"`
		Asc  []int    `json:"asc"`
	} `json:"cases"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	b, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Toolchain != "go1.23.12" || len(f.Cases) == 0 {
		t.Fatalf("fixture from %q with %d cases", f.Toolchain, len(f.Cases))
	}
	return f
}

func identity(n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	return idx
}

func TestSliceMatchesReference(t *testing.T) {
	f := loadFixture(t)
	for i, c := range f.Cases {
		desc := identity(len(c.Keys))
		Slice(desc, func(a, b int) bool { return c.Keys[desc[a]] > c.Keys[desc[b]] })
		if !slices.Equal(desc, c.Desc) {
			t.Errorf("case %d (n=%d) desc: got %v, want %v", i, len(c.Keys), desc, c.Desc)
		}
		asc := identity(len(c.Keys))
		Slice(asc, func(a, b int) bool { return c.Keys[asc[a]] < c.Keys[asc[b]] })
		if !slices.Equal(asc, c.Asc) {
			t.Errorf("case %d (n=%d) asc: got %v, want %v", i, len(c.Keys), asc, c.Asc)
		}
	}
}

// TestAlternatingDiligence sorts 15 candidates with diligence 5, 7, 5, 7, ...
// by diligence descending.
func TestAlternatingDiligence(t *testing.T) {
	d := []uint64{5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5}
	idx := identity(len(d))
	Slice(idx, func(a, b int) bool { return d[idx[a]] > d[idx[b]] })
	want := []int{9, 7, 13, 3, 11, 5, 1, 8, 6, 0, 10, 4, 12, 2, 14}
	if !slices.Equal(idx, want) {
		t.Fatalf("got %v, want %v", idx, want)
	}
}

func TestFuncMatchesSlice(t *testing.T) {
	f := loadFixture(t)
	for i, c := range f.Cases {
		idx := identity(len(c.Keys))
		Func(len(idx), func(a, b int) bool { return c.Keys[idx[a]] > c.Keys[idx[b]] },
			func(a, b int) { idx[a], idx[b] = idx[b], idx[a] })
		if !slices.Equal(idx, c.Desc) {
			t.Errorf("case %d: got %v, want %v", i, idx, c.Desc)
		}
	}
}
