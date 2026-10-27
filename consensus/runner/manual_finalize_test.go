package runner

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

type deferredFinalizer struct {
	*fakeApp
	complete []func(error)
}

func (a *deferredFinalizer) FinalizeBlockManual(_ *types.Block, _ types.Round, complete func(error)) {
	a.complete = append(a.complete, complete)
}
func TestManualFinalizePausesInputsAndSerializesCommitCalls(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	app := &deferredFinalizer{fakeApp: n.app}
	n.r.d.App = app
	b := block(t, 10, 0, k.addrs[0], types.Hash{})
	n.r.commitMu.Lock()
	n.r.commitQ = append(n.r.commitQ, commitJob{block: b, at: n.clock.Mono()}, commitJob{block: b, at: n.clock.Mono()})
	n.r.commitMu.Unlock()
	if !n.r.Pump() || len(app.complete) != 1 || !n.r.manualCommitPending.Load() {
		t.Fatal("manual actor not pending")
	}
	n.r.appMu.Lock()
	n.r.appQ = append(n.r.appQ, queued{in: consensus.CommitResult{}, via: viaApp})
	before := len(n.r.appQ)
	n.r.appMu.Unlock()
	if n.r.Pump() {
		t.Fatal("core processed inputs while application call blocked")
	}
	n.r.appMu.Lock()
	after := len(n.r.appQ)
	n.r.appMu.Unlock()
	if after != before || len(app.complete) != 1 || len(n.events.kinds(event.CommitResult)) != 0 {
		t.Fatal("blocked call admitted inputs or fabricated completion")
	}
	if err := n.r.Stop(); !errors.Is(err, ErrFinalizePending) || !n.r.Running() {
		t.Fatal("stop discarded outstanding call", err)
	}
	if err := n.r.Close(); !errors.Is(err, ErrFinalizePending) || n.r.closed || n.r.appClosing {
		t.Fatal("close discarded outstanding call", err)
	}
	n.clock.advance(time.Second)
	app.complete[0](nil)
	app.complete[0](errors.New("duplicate callback"))
	if n.r.manualCommitPending.Load() || len(n.events.kinds(event.CommitResult)) != 1 {
		t.Fatal("completion duplicate or pending")
	}
	if !n.r.Pump() || len(app.complete) != 2 || !n.r.manualCommitPending.Load() {
		t.Fatal("second call did not remain serial")
	}
	app.complete[1](errors.New("fixed failure"))
	n.r.Pump()
	rows := n.events.kinds(event.CommitResult)
	if len(rows) != 2 || rows[0].Fields["ok"] != true || rows[1].Fields["ok"] != false {
		t.Fatal(rows)
	}
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
}
func TestNonManualFinalizeKeepsSynchronousApplicationContract(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	app := &deferredFinalizer{fakeApp: n.app}
	n.r.d.App = app
	n.r.cfg.Manual = false
	defer func() { n.r.cfg.Manual = true }()
	b := block(t, 10, 0, k.addrs[0], types.Hash{})
	n.r.finalize(commitJob{block: b, at: n.clock.Mono()})
	if len(app.complete) != 0 || len(n.app.finalized) != 1 || len(n.events.kinds(event.CommitResult)) != 1 || n.r.manualCommitPending.Load() {
		t.Fatal("non-manual finalization changed")
	}
}
