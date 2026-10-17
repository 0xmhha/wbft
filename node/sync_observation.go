package node

import "github.com/0xmhha/wbft/observe/journal"

// The caller holds syncMu. Exhaustion never aliases an earlier identity.
func nextSyncSequence(last *uint64) uint64 {
	if *last == ^uint64(0) {
		return 0
	}
	*last++
	return *last
}

func (n *Node) recordSync(rec *journal.SyncRec) {
	n.mu.Lock()
	w := n.journal
	n.mu.Unlock()
	if w == nil {
		return
	}
	rec.Mono, rec.WallNs = n.clock.Mono(), n.clock.Now().UnixNano()
	w.Put(journal.Record{Body: rec})
}

// handleSync preserves the latest-state policy: requests may be superseded,
// and multiple wakes can handle the same request. Only actual control calls
// get event cursors; timestamps never establish a control boundary.
func (n *Node) handleSync() {
	n.syncMu.Lock()
	s := n.syncLatest
	first := n.firstSync
	if s == nil {
		n.syncMu.Unlock()
		return
	}
	if !s.Syncing && s.Success {
		n.firstSync = true
	}
	rec := &journal.SyncRec{Stage: "processed", Request: n.syncRequest, Operation: nextSyncSequence(&n.syncOperations),
		Syncing: s.Syncing, Success: s.Success, FirstBefore: first, FirstAfter: n.firstSync, Action: "none"}
	n.syncMu.Unlock()
	rec.SequenceExhausted = rec.Request == 0 || rec.Operation == 0
	n.mu.Lock()
	ev := n.ev
	n.mu.Unlock()
	rec.RunningBefore = n.r.Running()
	before := func(action string) {
		rec.Action = action
		if ev != nil {
			rec.EventBefore, rec.EventsAvailable = ev.Seq(), true
		}
	}
	switch {
	case s.Syncing && !first && n.r.Running():
		before("stop")
		if err := n.r.Stop(); err != nil {
			rec.Failed = true
			n.log.Warn("stop the core for synchronisation", "err", err)
		}
	case !s.Syncing && !n.r.Running():
		head := n.d.App.Head()
		before("start")
		if err := n.r.Start(n.ctx, head.Number.AddUint64(1)); err != nil {
			rec.Failed = true
			n.log.Warn("start the core after synchronisation", "err", err)
		}
	}
	if rec.EventsAvailable {
		rec.EventAfter = ev.Seq()
		if rec.EventAfter < rec.EventBefore {
			rec.EventsAvailable = false
		}
	}
	rec.RunningAfter = n.r.Running()
	n.recordSync(rec)
}
