package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type failureDiagnosticCapture struct {
	writer journal.Writer
	clock  Clock
	run    string
	core   journal.CoreOptions
}

func (o *failureDiagnosticCapture) CaptureRun() string                   { return o.run }
func (o *failureDiagnosticCapture) CoreDeclaration() journal.CoreOptions { return o.core.Copy() }
func (o *failureDiagnosticCapture) ObserveCoreStep(s CoreStepObservation) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *failureDiagnosticCapture) ObserveInboxSource(s journal.InboxRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *failureDiagnosticCapture) ObserveInboxFailureHit(s journal.InboxFailureHitRec) {
	o.writer.Put(journal.Record{Body: &s})
}
func (o *failureDiagnosticCapture) ObserveReceiveTransition(s transport.ReceiveTransition) {
	o.writer.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: s, Mono: o.clock.Mono(), WallNs: o.clock.Now().UnixNano()}})
}
func (o *failureDiagnosticCapture) ObserveReceiveFailure(s transport.ReceiveFailureEvent) {
	o.writer.Put(journal.Record{Body: &journal.ReceiveFailureCacheRec{Version: journal.ReceiveFailureRecordVersion, Transition: s, Mono: o.clock.Mono(), WallNs: o.clock.Now().UnixNano()}})
}

func failureDiagnosticOptions(n *tnode) (Config, *failureDiagnosticCapture) {
	limits := transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 4, WritePending: 16, WritePerPeer: 4}
	core := journal.CoreOptions{Self: n.opts.Self, ChainConfig: []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`), Improvements: uint64(n.opts.Improvements),
		CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2}}
	// Parse the exact persisted configuration used by this source fixture.
	// NewConfig and ParseChainConfig can represent omitted defaults differently;
	// the runtime declaration gate deliberately requires exact configuration.
	config, err := types.ParseChainConfig(core.ChainConfig)
	if err != nil {
		n.t.Fatal(err)
	}
	n.opts.Config = config
	receive := limits.ReceiveOptions()
	return Config{Core: n.opts, ReceiveCache: &receive, ReceiveFailureCache: &transport.ReceiveFailureOptions{Entries: 2}}, &failureDiagnosticCapture{run: "original-worker-failure", core: core, clock: n.clock}
}

func TestReceiveFailureCoordinatorRejectsIncompleteOrMixedSources(t *testing.T) {
	n := newTNode(t, newKeys(t, 4), 1)
	baseline, positive := failureDiagnosticOptions(n)
	positiveDeps := Deps{ReceiveFailureDiagnostics: positive}
	if err := connectFailureDiagnostics(&baseline, &positiveDeps); err != nil {
		t.Fatal("valid baseline never reached the coordinator", err)
	}
	reasons := map[string]string{
		"no_failure":      "explicit failure and code-aware accepted caches",
		"no_accepted":     "explicit failure and code-aware accepted caches",
		"payload_only":    "explicit failure and code-aware accepted caches",
		"journal":         "explicit failure and code-aware accepted caches",
		"run":             "writer run is required",
		"core":            "actual core options differ from declaration",
		"declaration":     "receive failure cache differs from declaration",
		"capacity":        "receive failure cache differs from declaration",
		"accepted_limits": "accepted receive limits differ from declaration",
		"failure_trace":   "independent cache/core/inbox observers",
		"accepted_trace":  "independent cache/core/inbox observers",
		"core_observer":   "independent cache/core/inbox observers",
		"inbox_observer":  "independent cache/core/inbox observers",
		"hit_observer":    "independent cache/core/inbox observers",
		"deferred":        "deferred receive declaration differs from runtime",
	}
	for _, name := range []string{"no_failure", "no_accepted", "payload_only", "journal", "run", "core", "declaration", "capacity", "accepted_limits", "failure_trace", "accepted_trace", "core_observer", "inbox_observer", "hit_observer", "deferred"} {
		t.Run(name, func(t *testing.T) {
			cfg, observer := failureDiagnosticOptions(n)
			deps := Deps{ReceiveFailureDiagnostics: observer}
			switch name {
			case "no_failure":
				cfg.ReceiveFailureCache = nil
			case "no_accepted":
				cfg.ReceiveCache = nil
			case "payload_only":
				cfg.ReceiveCache.KeyWithCode = false
			case "journal":
				observer.writer = &discardFailureJournal{}
				deps.Journal = observer.writer
			case "run":
				observer.run = ""
			case "core":
				observer.core.Self = types.Address{}
			case "declaration":
				observer.core.ReceiveFailureCache = nil
			case "capacity":
				observer.core.ReceiveFailureCache.Entries++
			case "accepted_limits":
				observer.core.CachePolicy.Limits.ReceivePending++
			case "failure_trace":
				cfg.ReceiveFailureCache.Trace = observer
			case "accepted_trace":
				cfg.ReceiveCache.Trace = observer
			case "core_observer":
				deps.CoreSteps = observer
			case "inbox_observer":
				deps.InboxSources = observer
			case "hit_observer":
				deps.InboxFailureSources = observer
			case "deferred":
				observer.core.NextHeight = &journal.DeferredOptions{Profile: journal.DeferredInputProfile, Entries: 1, Bytes: 1, PerPeer: 1, PerSource: 1}
			}
			if r, err := New(cfg, deps); r != nil || err == nil || !strings.Contains(err.Error(), "receive failure diagnostics") || !strings.Contains(err.Error(), reasons[name]) {
				t.Fatal("incomplete or split writer reached runtime resources", r, err)
			}
		})
	}
}

type discardFailureJournal struct{}

func (*discardFailureJournal) Put(journal.Record) {}
func (*discardFailureJournal) Close() error       { return nil }

func TestReceiveFailureCoordinatorFreezesNamespaceAndCopiesOptions(t *testing.T) {
	n := newTNode(t, newKeys(t, 4), 1)
	cfg, observer := failureDiagnosticOptions(n)
	originalReceive, originalFailure := cfg.ReceiveCache, cfg.ReceiveFailureCache
	deps := Deps{ReceiveFailureDiagnostics: observer}
	if err := connectFailureDiagnostics(&cfg, &deps); err != nil {
		t.Fatal(err)
	}
	observer.run = "later-caller-name"
	observer.core.ReceiveFailureCache.Entries = 9
	originalReceive.Pending, originalFailure.Entries = 99, 99
	if cfg.ReceiveCache == originalReceive || cfg.ReceiveFailureCache == originalFailure || cfg.ReceiveCache.Pending != 16 || cfg.ReceiveFailureCache.Entries != 2 {
		t.Fatal("caller mutated the frozen cache configuration")
	}
	failureRun, ok := cfg.ReceiveFailureCache.Trace.(interface{ CaptureRun() string })
	if !ok || failureRun.CaptureRun() != "original-worker-failure" || deps.ReceiveFailureDiagnostics.CaptureRun() != failureRun.CaptureRun() {
		t.Fatal("cache namespace was rebound after validation")
	}
	if deps.CoreSteps == nil || deps.InboxSources == nil || deps.InboxFailureSources == nil || cfg.ReceiveCache.Trace == nil {
		t.Fatal("coordinator left an incomplete source chain")
	}
}

// This exercises the actual receiver worker and actual journal encoder. The
// intact owned signature is evaluated under a different local authority set;
// no network frame, signature modification or physical-I/O evidence is created.
func TestReceiveFailureCoordinatorActualWorkerAndNormalRestart(t *testing.T) {
	members, owned := newKeys(t, 4), newKeys(t, 5)
	n := newTNode(t, members, 1)
	n.clock.tick = 1
	cfg, observer := failureDiagnosticOptions(n)
	w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/failure-runtime", Synchronous: true}, journal.Identity{Run: observer.run, Core: observer.core})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	observer.writer = w
	n.noJournal, n.receiveCache, n.receiveFailureCache, n.receiveFailureDiagnostics = true, cfg.ReceiveCache, cfg.ReceiveFailureCache, observer
	actual, reused := 0, 0
	n.receiveRecoveryChecked = func(_ codec.Code, phase consensus.RecoveryFailure) {
		if phase == consensus.RecoveryMembership {
			actual++
		}
	}
	n.receiveFailureHit = func(_ uint64, class transport.ReceiveFailureClass) {
		if class != transport.ReceiveMembershipFailure {
			t.Error("membership reuse changed class")
		}
		reused++
	}
	n.boot()
	t.Cleanup(func() {
		if err := n.r.Close(); err != nil {
			t.Error(err)
		}
		if err := n.log.Close(); err != nil {
			t.Error(err)
		}
	})
	proposal := block(t, 10, 1, members.addrs[0], codec.BlockHash(n.chain.head))
	raw := owned.vote(t, 4, codec.CodePrepare, view(10, 0), proposal)
	if v, err := consensus.Recover(codec.CodePrepare, raw, nil); err != nil || v.Source != owned.addrs[4] {
		t.Fatal("owned fixture was not a valid signature", err)
	}
	in := transportInbound(members, 0, codec.CodePrepare, raw, n.clock.now)
	feed := func() {
		t.Helper()
		if !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) {
			t.Fatal("actual local worker did not consume the original input")
		}
	}
	for engine := 1; engine <= 2; engine++ {
		feed()
		feed()
		if actual != engine || reused != engine {
			t.Fatal("reuse became another verifier invocation", actual, reused)
		}
		current := n.r.receiveContext.Load()
		if n.r.receiveCache.Known(current.scope, in.Code, raw) || n.r.receiveCache.Recent(current.scope, in.Peer, in.Code, raw) {
			t.Fatal("failure reuse became accepted authority")
		}
		if engine == 1 {
			if err := n.r.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
				t.Fatal(err)
			}
			n.r.Pump()
		}
	}
	// A normal proposal and prepare still reach the original core ACCEPT path.
	n.deliver(0, codec.CodePreprepare, members.preprepare(t, 0, view(10, 0), proposal))
	n.deliver(0, codec.CodePrepare, members.vote(t, 0, codec.CodePrepare, view(10, 0), proposal))
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	rows, err := journal.ReadAll(n.jfs, "/failure-runtime")
	if err != nil {
		t.Fatal(err)
	}
	recorded, hits, membershipChecks, accepted, coreSteps := 0, 0, 0, 0, 0
	originals := map[transport.ReceiveFailureRef]bool{}
	for _, row := range rows {
		switch body := row.Body.(type) {
		case *journal.GapRec:
			t.Fatal("original runtime diagnostic evidence was dropped", body)
		case *journal.ReceiveFailureCacheRec:
			if body.Transition.Run != observer.run || body.Transition.Unavailable != "" {
				t.Fatal("actual cache callback lost its frozen source", body)
			}
			if body.Transition.Stored {
				recorded++
				originals[body.Transition.Reference] = true
			}
		case *journal.InboxFailureHitRec:
			hits++
			if row.Kind != journal.KindInboxFailureHit || body.Unavailable != "" || body.Source.Unavailable != "" || body.Source.Action != "failure_hit" || !originals[body.Original] || body.Lookup.Run != observer.run || body.Source.Signer != (types.Address{}) {
				t.Fatal("actual hit became a missing source or ordinary check", body)
			}
		case *journal.InboxRec:
			if body.Action == "check" && body.Result == "membership" {
				membershipChecks++
			}
		case *journal.ReceiveCacheRec:
			if body.Transition.Action == transport.ReceiveCheckAccept && body.Transition.Decision == transport.ReceiveRegistered {
				accepted++
			}
		case *journal.CoreStepRec:
			coreSteps++
		}
	}
	if recorded != 2 || hits != 2 || membershipChecks != 2 || accepted == 0 || coreSteps == 0 {
		t.Fatal("actual original worker sources or successful core path missing", recorded, hits, membershipChecks, accepted, coreSteps)
	}
	report, err := journal.CheckReceiveFailureSources(rows, journal.ReceiveFailureLimits{Caches: 8, Inbox: journal.InboxLimits{
		Core: journal.CoreSourceLimits{Records: 20000, Runs: 32, Steps: 20000, Environments: 20000, Outputs: 100000, Bytes: 64 << 20}, Operations: 20000, Entries: 1000, Peers: 100, Frames: 1000, Bytes: 64 << 20,
	}})
	if err != nil || report.Status != "unavailable" || report.PhysicalStatus != "unavailable" {
		t.Fatal("local API inputs became complete original socket evidence", report, err)
	}
	t.Logf("actual_membership_checks=%d actual_hits=%d actual_core_accepted=%d source_status=%s reason=%s physical_status=%s crypto_failure_hit=false", actual, reused, accepted, report.Status, report.Reason, report.PhysicalStatus)
}
