// Package participation keeps and serves node-local records of validator
// participation, built from consensus events: who sent what and when, and
// whose signatures went into seals.
//
// A Recorder takes the node's event records (ROUND_ENTER, MSG_OUTCOME,
// EVIDENCE) and its new heads through a bounded queue, so that neither the
// consensus goroutine nor the application waits on it. It records a height
// when the next height's header arrives and the height's late seals are
// known. A node whose core does not run records what the headers tell.
//
// The store is JSON Lines in files of 256 heights each, named by the bucket
// number; whole files below the kept heights are removed. Writes are not
// synced: a crash may lose the last heights, which then read as gaps.
package participation
