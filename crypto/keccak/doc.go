// Package keccak computes the legacy Keccak-256 hash used throughout the
// protocol. It is a thin wrapper so that every hash call site of the consensus
// layer can be found in one place, both by tests and by ports to other
// languages.
package keccak
