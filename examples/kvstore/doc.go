// Package kvstore is an example application for the wbft consensus layer: a
// replicated key-value store. It shows what an application implements
// (app.Application, source.AuthoritySource and mempool.AdmissionHook) and
// how it uses the node's Consensus service to build, import and finalize
// blocks.
//
// It is an example for development networks, not a product: transactions
// are not signed (any client may send as any address), the validator set is
// the genesis set forever, and a node that fell behind catches up by asking
// its peers for blocks over the development transport (package p2p/devnet).
package kvstore
