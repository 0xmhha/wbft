// Package wal is an append-only log that knows nothing about consensus types.
// It frames records with a length and a checksum, rotates segments and
// recovers from a damaged tail.
package wal
