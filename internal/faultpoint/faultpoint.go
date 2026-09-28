// Package faultpoint marks the places between two durable steps where a
// crash test may stop a node: before and after the sign state is written,
// before and after an own message reaches the write-ahead log, before and
// after it is sent, around the commit request and around the end-of-height
// record.
//
// Hit calls the component's handler only in builds with the tag
// wbft_faults; in every other build it does nothing and the compiler removes
// the call. A handler stops the node by panicking with a value the test
// recognises.
package faultpoint

// Handler is called with the name of a fault point. Nil means no handler.
type Handler func(name string)

// Fault point names.
const (
	PrivvalBeforePersist = "privval.before_persist"
	PrivvalAfterPersist  = "privval.after_persist"
	WALBeforeOwnMsg      = "wal.before_own_msg"
	WALAfterOwnMsg       = "wal.after_own_msg"
	SendBefore           = "send.before"
	SendAfter            = "send.after"
	CommitBefore         = "commit_request.before"
	CommitAfter          = "commit_request.after"
	EndHeightBefore      = "end_height.before"
	EndHeightAfter       = "end_height.after"
)

// All lists every fault point.
var All = []string{
	PrivvalBeforePersist, PrivvalAfterPersist,
	WALBeforeOwnMsg, WALAfterOwnMsg,
	SendBefore, SendAfter,
	CommitBefore, CommitAfter,
	EndHeightBefore, EndHeightAfter,
}
