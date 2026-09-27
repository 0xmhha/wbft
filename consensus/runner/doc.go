// Package runner drives the consensus core in a node. It owns the consensus
// goroutine and its input queues, per-peer receive queues and checks, the
// timer scheduler, write-ahead logging and replay, calls to the private
// validator, message sending, the commit goroutine and the publication of
// state snapshots.
package runner
