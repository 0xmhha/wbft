// Package mempool stores transactions, orders them through pluggable ordering
// policies (with a built-in first-in-first-out policy), selects transactions
// for proposals and decides when to gossip them. Transaction validity is
// decided by the application through an admission hook; this package does not
// interpret transaction contents.
package mempool
