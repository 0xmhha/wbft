package runner

// Lock order of the consensus layer. The consensus state has no lock: one
// goroutine owns it. The remaining locks may only be taken in this order;
// the design takes no two of them at once, and the numbers are the order to
// keep if an overlap becomes necessary.
//
//  1. privval.signer.mu      sign state check, write and signature
//  2. wal.writer.mu          record writes and segment rotation
//  3. transport.dedup.mu     the two LRU caches of the deduplication layer
//  4. observe.ring.mu        event ring insertion (package observe, later)
//  5. runner.timers.mu       the timer table and the queue of expiries
//  6. runner.inbox.mu        per-peer queues, slot table and ready lists
//  7. mempool.pool.mu        the transaction pool (package mempool, later)
//  8. observe.journal.q.mu   message journal queue insertion
//
// Two small locks of this package are leaves that are never held while
// another lock is taken: runner.app.mu (the application queue) and
// runner.commit.mu (the commit queue).
//
// Rules: no wbft lock is held while the application is called, and no lock
// is held across a channel operation that can block.
