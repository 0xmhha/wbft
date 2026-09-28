// Command gen writes the fixed orders that internal/refsort is tested
// against. Run it with the toolchain the reference implementation is built
// with (go1.23.12):
//
//	cd internal/refsort/testdata/gen
//	GOTOOLCHAIN=go1.23.12 go run . > ../reference.json
//
// The inputs are generated from a fixed seed, so the file changes only when
// this program changes.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
)

// Case is one input and the orders produced by sort.Slice over the identity
// index slice: Desc compares keys with ">" (the candidate order), Asc with
// "<" (the transition order).
type Case struct {
	Keys []uint64 `json:"keys"`
	Desc []int    `json:"desc"`
	Asc  []int    `json:"asc"`
}

// File is the output document.
type File struct {
	Toolchain string `json:"toolchain"`
	Cases     []Case `json:"cases"`
}

// splitmix64 is a small deterministic generator for the inputs.
type splitmix64 uint64

func (s *splitmix64) next() uint64 {
	*s += 0x9e3779b97f4a7c15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func order(keys []uint64, less func(a, b uint64) bool) []int {
	idx := make([]int, len(keys))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(i, j int) bool { return less(keys[idx[i]], keys[idx[j]]) })
	return idx
}

func main() {
	if runtime.Version() != "go1.23.12" {
		fmt.Fprintf(os.Stderr, "gen: toolchain is %s, want go1.23.12\n", runtime.Version())
		os.Exit(1)
	}
	var inputs [][]uint64
	// The executed example of the specification (A-04 §6.4).
	inputs = append(inputs, []uint64{5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5, 7, 5})
	rng := splitmix64(20260928)
	for n := 0; n <= 140; n += 1 + n/16 {
		for distinct := 1; distinct <= 4; distinct++ {
			keys := make([]uint64, n)
			for i := range keys {
				keys[i] = rng.next() % uint64(distinct)
			}
			inputs = append(inputs, keys)
		}
	}
	// Longer inputs reach the heapsort fallback and the pattern breaking.
	for _, n := range []int{200, 257, 500, 1000} {
		for _, distinct := range []uint64{2, 3, 50, 1 << 40} {
			keys := make([]uint64, n)
			for i := range keys {
				keys[i] = rng.next() % distinct
			}
			inputs = append(inputs, keys)
		}
		asc := make([]uint64, n)
		desc := make([]uint64, n)
		for i := range asc {
			asc[i] = uint64(i / 3)
			desc[i] = uint64((n - i) / 3)
		}
		inputs = append(inputs, asc, desc)
	}
	f := File{Toolchain: runtime.Version()}
	for _, k := range inputs {
		f.Cases = append(f.Cases, Case{
			Keys: k,
			Desc: order(k, func(a, b uint64) bool { return a > b }),
			Asc:  order(k, func(a, b uint64) bool { return a < b }),
		})
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(f); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
