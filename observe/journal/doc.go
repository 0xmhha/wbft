// Package journal records the raw consensus messages a node sends and
// receives, with sender, receiver and monotonic time, so that runs can be
// analysed and replayed later. It reuses the record framing and segments of
// package wal but keeps its own directory and retention rules.
package journal
