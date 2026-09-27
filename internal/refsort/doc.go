// Package refsort holds a copy of the pattern-defeating quicksort of the Go
// 1.23 standard library. Orderings that must match the reference
// implementation byte for byte (candidate sorting and transition sorting) call
// it instead of the sort package of the running toolchain, whose unstable
// order may change between Go releases. Only the types and epoch packages may
// import it.
package refsort
