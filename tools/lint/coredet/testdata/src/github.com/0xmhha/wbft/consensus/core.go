package consensus

import (
	"maps"
	"slices"
)

type Input struct{ C chan int } // want `channel type in a deterministic package`

func spawn(f func()) {
	go f() // want `go statement in a deterministic package`
}

func pick(a, b chan int) int { // want `channel type`
	select { // want `select statement in a deterministic package`
	case v := <-a: // want `channel receive in a deterministic package`
		return v
	case b <- 1: // want `channel send in a deterministic package`
	}
	for v := range a { // want `range over a channel in a deterministic package`
		_ = v
	}
	_ = make(chan struct{}) // want `channel type`
	return 0
}

func iterate(m map[string]int) int {
	n := 0
	for k := range m { // want `range over a map without //wbft:unordered <reason>`
		n += len(k)
	}
	//wbft:unordered the sum does not depend on the order
	for _, v := range m {
		n += v
	}
	for _, v := range m { //wbft:unordered commutative sum
		n += v
	}
	//wbft:unordered
	for range m { // want `range over a map without`
		n++
	}
	for k := range maps.Keys(m) { // want `range over a map iterator without`
		n += len(k)
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		n += len(k)
	}
	for i := range []int{1, 2} {
		n += i
	}
	return n
}
