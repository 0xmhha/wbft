// Package refsort holds a copy of the pattern-defeating quicksort that the
// reference implementation uses. Orderings that must match the reference
// implementation byte for byte (candidate sorting and transition sorting) call
// it instead of the sort package of the running toolchain. Only the types and
// epoch packages may import it.
package refsort
