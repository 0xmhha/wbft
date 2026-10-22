package runner

import (
	"context"
	"crypto/sha256"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type runnerReceiveTransitions struct {
	mu     sync.Mutex
	events []transport.ReceiveTransition
	writer journal.Writer
	start  time.Time
}

func (o *runnerReceiveTransitions) ObserveReceiveTransition(event transport.ReceiveTransition) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
	if o.writer != nil {
		now := time.Now()
		o.writer.Put(journal.Record{Body: &journal.ReceiveCacheRec{Transition: event, Mono: now.Sub(o.start), WallNs: now.UnixNano()}})
	}
}
func (o *runnerReceiveTransitions) snapshot() []transport.ReceiveTransition {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]transport.ReceiveTransition(nil), o.events...)
}

func TestReceiveCacheActualCoreAcceptanceAndNormalRestart(t *testing.T) {
	k := newKeys(t, 4)
	var referenceVars, referenceRestart *consensus.Vars
	var referenceSent []sent
	var referenceWAL []wal.Record
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, k, 1)
		n.noJournal = true
		observed := &runnerReceiveTransitions{start: time.Now()}
		if enabled {
			// This separate diagnostic observer journal does not enable the runner's
			// unsupported functional cache-journal profile or contain core step proof.
			writer, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/receive-observations", Synchronous: true}, journal.Identity{Run: "receive-observer"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = writer.Close() })
			observed.writer = writer
		}
		if enabled {
			n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: observed}
		}
		n.boot()
		b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
		n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
		raw := k.vote(t, 0, codec.CodePrepare, view(10, 0), b)
		in := transportInbound(k, 0, codec.CodePrepare, raw, n.clock.now)
		if !n.r.Receiver().Offer(in) {
			t.Fatal("normal input refused")
		}
		if enabled {
			current := n.r.receiveContext.Load()
			if current == nil || n.r.receiveCache.Known(current.scope, in.Code, raw) || n.r.d.Transport.SentOrReceived(in.Peer, raw) {
				t.Fatal("queue acceptance registered an unverified input")
			}
			if !n.r.inbox.checkOne(true) {
				t.Fatal("normal receive check missing")
			}
			if n.r.receiveCache.Known(current.scope, in.Code, raw) || n.r.d.Transport.SentOrReceived(in.Peer, raw) {
				t.Fatal("worker recovery alone registered the key")
			}
			if !n.r.processOne() {
				t.Fatal("checked message did not reach the core")
			}
		}
		n.r.Pump()
		if enabled {
			current := n.r.receiveContext.Load()
			if !n.r.receiveCache.Known(current.scope, in.Code, raw) || !n.r.receiveCache.Recent(current.scope, in.Peer, in.Code, raw) || !n.r.d.Transport.SentOrReceived(in.Peer, raw) || n.r.receiveCache.Pending() != 0 {
				t.Fatal("successful core ACCEPT did not register or release ownership")
			}
		}
		var acceptedSource transport.ReceiveAcceptSource
		if enabled {
			matches := 0
			for _, transition := range observed.snapshot() {
				if transition.Action != transport.ReceiveCheckAccept || transition.Input.PayloadSHA256 != types.Hash(sha256.Sum256(raw)) {
					continue
				}
				if transition.Decision != transport.ReceiveRegistered || !transition.Owned || !transition.Matched || !transition.Released || !transition.Recent || !transition.ScopeActive || transition.Input != transition.Checked {
					t.Fatal("actual ACCEPT transition incomplete", transition)
				}
				if !transition.ContextKnown || transition.Context.Sequence != "10" || transition.Context.Round != "0" || !transition.Context.ValidatorsPresent || transition.Context.Validators == (types.Hash{}) {
					t.Fatal("actual acceptance lost immutable checking context", transition.Context)
				}
				source := transition.Source
				acceptedSource = source
				if source.EngineRun != n.r.EngineRun() || source.Step == 0 || source.Output == 0 || source.Via != "direct" {
					t.Fatal("actual direct ACCEPT source unavailable", source)
				}
				n.events.mu.Lock()
				found := 0
				for index, record := range n.events.recs {
					if record.Kind == event.MsgOutcome && record.Fields["dedup_key"] == hexHash(codec.DedupKey(raw)) && record.Fields["via"] == "direct" && record.Fields["outcome"] == event.Accept {
						stamp := n.events.stamps[index]
						if stamp.Step != nil && *stamp.Step == source.Step && record.Fields["engine_run"] == source.EngineRun {
							found++
						}
					}
				}
				n.events.mu.Unlock()
				if found != 1 {
					t.Fatal("cache registration did not name its actual core ACCEPT step", found)
				}
				matches++
			}
			if matches != 1 {
				t.Fatal("actual input cache transition missing", matches)
			}
		}
		step := n.r.step
		n.deliver(0, codec.CodePrepare, raw)
		if n.r.step != step {
			t.Fatal("already accepted normal duplicate reached another core step")
		}
		vars := n.r.Vars()
		records, _, err := wal.ReadAll(n.fs, "/wal")
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			referenceVars, referenceSent, referenceWAL = vars, append([]sent(nil), n.net.sent...), records
		} else if !reflect.DeepEqual(referenceVars, vars) || !reflect.DeepEqual(referenceSent, n.net.sent) || !reflect.DeepEqual(referenceWAL, records) {
			t.Fatal("serial normal off/on state, signed targets or WAL bytes differ")
		}
		if err := n.r.Stop(); err != nil {
			t.Fatal(err)
		}
		if enabled && n.r.receiveContext.Load() != nil {
			t.Fatal("normal Stop retained a validation context")
		}
		if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
		n.r.Pump()
		if !enabled {
			referenceRestart = n.r.Vars()
		} else if !reflect.DeepEqual(referenceRestart, n.r.Vars()) {
			t.Fatal("normal WAL restart changed the full core state")
		}
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		if enabled {
			if err := observed.writer.Close(); err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(n.jfs, "/receive-observations")
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			for _, record := range records {
				if r, ok := record.Body.(*journal.ReceiveCacheRec); ok && r.Transition.Action == transport.ReceiveCheckAccept && r.Transition.Input.PayloadSHA256 == types.Hash(sha256.Sum256(raw)) && r.Transition.Decision == transport.ReceiveRegistered && r.Transition.Source == acceptedSource {
					if !r.Transition.ContextKnown || r.Transition.Context.Sequence != "10" {
						t.Fatal("actual context lost on journal read")
					}
					if r.Transition.Source.EngineRun == 0 || r.Transition.Source.Step == 0 || r.Transition.Source.Output == 0 {
						t.Fatal("actual ACCEPT source lost on journal read")
					}
					matches++
				}
			}
			if matches != 1 {
				t.Fatal("actual core receive transition missing after journal close/open", matches)
			}
		}
	}
}

func TestReceiveCacheRefusesLegacyJournalProfile(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	n.boot()
	t.Cleanup(func() { _ = n.r.Close(); _ = n.log.Close() })
	jw, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/other", Synchronous: true}, journal.Identity{Self: k.addrs[1]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jw.Close() })
	d := n.r.d
	d.Journal = jw
	cfg := n.r.cfg
	cfg.ReceiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	if _, err := New(cfg, d); err == nil || !strings.Contains(err.Error(), "journal profile") {
		t.Fatal("legacy journal silently represented the new cache policy", err)
	}
}

// Actual receiver, full core dispatch and WAL with a normal authority change.
// This is a local chain adapter, not a governance-contract/network acceptance.
func TestReceiveCacheNextHeightNormalAuthorityAndReplay(t *testing.T) {
	k := newKeys(t, 5)
	oldSet := nextHeightSet(t, k, []int{0, 1, 2, 3})
	newSet := nextHeightSet(t, k, []int{1, 2, 3, 4})
	limits := &NextHeightLimits{Entries: 12, Bytes: 1 << 20, PerPeer: 12, PerSource: 12}
	n := newNextHeightNode(t, k, oldSet, types.HeightFromUint64(10), limits, false)
	n.close()
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	n.boot()
	raw := k.sign(t, 4, &codec.Message{Code: codec.CodeRoundChange, View: view(11, 1)}, nil)
	in := transportInbound(k, 1, codec.CodeRoundChange, raw, 1)
	if !n.r.Receiver().Offer(in) {
		t.Fatal("normal joining-member input refused")
	}
	n.r.Pump()
	if entries, bytes := n.r.NextHeightUsage(); entries != 1 || bytes != uint64(len(raw)) {
		t.Fatal("future reservation not retained", entries, bytes)
	}
	if n.r.receiveCache.Pending() != 0 || len(n.events.kinds(event.MsgOutcome)) != 0 {
		t.Fatal("outer-only recovery authenticated into the receive cache or core")
	}
	head := block(t, 10, 1, k.addrs[3], codec.BlockHash(n.chain.Head())).Header
	n.advance(head, newSet, false)
	n.r.Pump()
	if entries, bytes := n.r.NextHeightUsage(); entries != 0 || bytes != 0 {
		t.Fatal("accepted deferred input retained raw ownership", entries, bytes)
	}
	current := n.r.receiveContext.Load()
	if current == nil || !n.r.receiveCache.Known(current.scope, in.Code, raw) || n.r.receiveCache.Pending() != 0 {
		t.Fatal("current full core ACCEPT did not register the joining member")
	}
	outcomes := n.events.kinds(event.MsgOutcome)
	if len(outcomes) != 1 || outcomes[0].Fields["outcome"] != event.Accept || outcomes[0].Fields["source"] != hexAddr(k.addrs[4]) {
		t.Fatal("normal new authority did not produce the expected ACCEPT", outcomes)
	}
	before := n.r.Vars()
	n.close()
	n.boot()
	if !n.r.LastReplay().Replayed || n.r.LastReplay().Stopped != "" || !reflect.DeepEqual(before, n.r.Vars()) {
		t.Fatal("combined receive/deferred WAL replay changed full core state", n.r.LastReplay())
	}
	if entries, bytes := n.r.NextHeightUsage(); entries != 0 || bytes != 0 || n.r.receiveCache.Pending() != 0 {
		t.Fatal("completed release was re-admitted after replay", entries, bytes)
	}
}

func TestReceiveCacheFrozenOriginThroughWorkerAndCore(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
	n.boot()
	t.Cleanup(func() { _ = n.r.Close(); _ = n.log.Close() })
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
	raw := k.vote(t, 0, codec.CodePrepare, view(10, 0), b)
	original := transport.ReceiveOrigin{WriterRun: "original-capture-run", CaptureID: 7}
	in := transportInbound(k, 0, codec.CodePrepare, raw, n.clock.now)
	in.Capture = 7
	in.Origin = original
	if !n.r.Receiver().(transport.CaptureOriginReceiver).UsesCaptureOrigin() || !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) {
		t.Fatal("normal original input not checked")
	}
	message, capture, stream, origin, ok := n.r.inbox.takeWithOrigin()
	if !ok || origin != original || capture != original.CaptureID {
		t.Fatal("worker changed capture provenance", origin, capture)
	}
	q := queued{in: message, via: viaPeer, capture: capture, stream: stream, origin: origin}
	ticket, received, duplicate := n.r.beginReceiveCheck(q)
	if duplicate || ticket.Origin() != original || received.Origin != original {
		t.Fatal("dispatch rebound capture provenance", ticket.Origin(), received.Origin)
	}
	n.r.receiveCache.Cancel(ticket)
	n.r.handle(q)
	current := n.r.receiveContext.Load()
	if current == nil || !n.r.receiveCache.Known(current.scope, in.Code, raw) {
		t.Fatal("original provenance changed successful core ACCEPT")
	}
}

func TestReceiveCacheDeferredUsesFrozenOriginOnly(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "original"}[available], func(t *testing.T) {
			k := newKeys(t, 5)
			oldSet := nextHeightSet(t, k, []int{0, 1, 2, 3})
			n := newNextHeightNode(t, k, oldSet, types.HeightFromUint64(10), &NextHeightLimits{Entries: 12, Bytes: 1 << 20, PerPeer: 12, PerSource: 12}, false)
			n.close()
			n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
			n.boot()
			t.Cleanup(n.close)
			raw := k.sign(t, 4, &codec.Message{Code: codec.CodeRoundChange, View: view(11, 1)}, nil)
			in := transportInbound(k, 1, codec.CodeRoundChange, raw, 1)
			in.Capture = 7
			if available {
				in.Origin = transport.ReceiveOrigin{WriterRun: "original-deferred-source", CaptureID: 7}
			}
			if !n.r.Receiver().Offer(in) {
				t.Fatal("normal future input not retained")
			}
			n.r.nextHeight.mu.Lock()
			var record deferredRecord
			for _, entry := range n.r.nextHeight.entries {
				record = entry.record
			}
			n.r.nextHeight.mu.Unlock()
			if available {
				if record.CaptureRun != in.Origin.WriterRun || record.Capture != 7 {
					t.Fatal("future origin changed", record.CaptureRun, record.Capture)
				}
			} else if record.CaptureRun != "" || record.Capture != 0 {
				t.Fatal("missing origin inferred", record.CaptureRun, record.Capture)
			}
		})
	}
}
