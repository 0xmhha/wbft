// Package runner is not a deterministic package: nothing is reported.
package runner

func Loop(in chan int, m map[int]int) {
	go func() {}()
	for range in {
	}
	for range m {
	}
}
