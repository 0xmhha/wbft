package runner

import (
	"bytes"
	"fmt"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"slices"
	"testing"
)

func TestReceiveDispatchKnownFromActualHonestRelayBeforeSelfDelivery(t *testing.T) {
	k := newKeys(t, 4)
	nodes := make([]*tnode, 4)
	traces := make([]*runnerReceiveTransitions, 4)
	writers := make([]journal.Writer, 4)
	runs := make([]string, 4)
	closed := make([]bool, 4)
	for i := range nodes {
		n := newTNode(t, k, i)
		nodes[i] = n
		n.noJournal = true
		// The ordinary parent predates this fresh runner's wall clock. No running
		// clock or timer is changed, and every node starts with the same parent.
		n.chain.head.Time = uint64(n.clock.Now().Unix()) - 1
		runs[i] = fmt.Sprintf("normal-relay-%d", i)
		cfg := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
		w, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/receive-dispatch", Synchronous: true}, journal.Identity{Run: runs[i], Self: n.opts.Self, Mode: "diagnostic", Core: journal.CoreOptions{ChainConfig: cfg, TimerTrace: journal.TimerTraceVersion, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit), CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}}}})
		if err != nil {
			t.Fatal(err)
		}
		writers[i] = w
		o := &receiveDispositionRecorder{writer: w}
		n.coreSteps = o
		n.timerSources = o
		n.appQueueSources = o
		n.finalizeSources = o
		n.inboxSources = o
		n.internalSources = o
		n.selectionSources = o
		n.receiveDispatchSources = o
		traces[i] = &runnerReceiveTransitions{clock: n.clock, writer: w}
		n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 32, PerPeer: 8, KeyWithCode: true, Trace: traces[i]}
		n.boot()
		t.Cleanup(func() {
			if closed[i] {
				return
			}
			if err := n.r.Close(); err != nil {
				t.Error(err)
			}
			if err := n.log.Close(); err != nil {
				t.Error(err)
			}
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(nodes[0].chain.head))
	b.Header.Time = uint64(nodes[0].clock.Now().Unix())
	nodes[0].r.Submit(b)
	if !nodes[0].r.processOne() {
		t.Fatal("normal proposer did not process its builder request")
	}
	pp := nodes[0].net.own(codec.CodePreprepare)
	if len(pp) != 1 {
		t.Fatal("normal proposer did not publish exactly one proposal", len(pp))
	}
	streams := map[[2]int]*transport.WriteSession{}
	captures := make([]uint64, 4)
	deliver := func(from, to int, code codec.Code, payload []byte) {
		// Every hop must be an actual send by this honest actor to this recipient.
		// No payload is constructed/re-signed or attributed to an unsending peer.
		found := false
		for _, sent := range nodes[from].net.sent {
			if sent.code == uint64(code) && bytes.Equal(sent.payload, payload) && slices.Contains(sent.peers, k.addrs[to]) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("requested hop was not an original honest send", from, to, code)
		}
		in := transportInbound(k, from, code, payload, nodes[to].clock.now)
		link := [2]int{from, to}
		stream := streams[link]
		if stream == nil {
			stream = transport.NewWriteSession()
			stream.BindObservationRun(runs[to])
			streams[link] = stream
			writers[to].Put(journal.Record{Body: &journal.PeerRec{PeerIdx: uint32(from), Addr: k.addrs[from], Event: "attached"}})
			writers[to].Put(journal.Record{Body: &journal.SessionRec{Session: &journal.SessionRef{Run: stream.ObservationRun(), Ordinal: stream.ObservationID()}, Peer: k.addrs[from], Event: journal.SessionObserved, Active: true, Mono: nodes[to].clock.Mono(), WallNs: nodes[to].clock.Now().UnixNano()}})
		}
		captures[to]++
		in.Capture = captures[to]
		in.Stream = stream
		in.Origin = transport.ReceiveOrigin{WriterRun: runs[to], CaptureID: in.Capture}
		// The immutable original raw frame is recorded independently of worker/core
		// observations. No physical I/O interval is asserted by this manual actor.
		writers[to].Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: uint32(from), Session: &journal.SessionRef{Run: stream.ObservationRun(), Ordinal: stream.ObservationID()}, Capture: in.Capture, Code: uint64(code), WireCode: uint64(code), Payload: bytes.Clone(payload), Size: uint64(len(payload)), Mono: nodes[to].clock.Mono(), WallNs: nodes[to].clock.Now().UnixNano(), DedupKey: codec.DedupKey(payload), Engine: "running", Offer: "queued"}})

		if !nodes[to].r.Receiver().Offer(in) || !nodes[to].r.inbox.checkOne(true) {
			t.Fatal("normal genuine relay was not queued and checked", from, to)
		}
	}
	for _, to := range []int{1, 2, 3} {
		deliver(0, to, codec.CodePreprepare, pp[0])
		if !nodes[to].r.processOne() {
			t.Fatal("normal proposal was not processed", to)
		}
	}
	original := nodes[1].net.own(codec.CodePrepare)
	if len(original) != 1 {
		t.Fatal("normal validator did not publish a prepare")
	}
	for _, i := range []int{2, 3} {
		if !nodes[i].r.processOne() {
			t.Fatal("normal local prepare was not processed", i)
		}
	}
	deliver(1, 2, codec.CodePrepare, original[0])
	if !nodes[2].r.processOne() {
		t.Fatal("first normal relay actor did not process the vote")
	}
	deliver(2, 3, codec.CodePrepare, original[0])
	if !nodes[3].r.processOne() {
		t.Fatal("second normal relay actor did not process the vote")
	}
	deliver(3, 1, codec.CodePrepare, original[0])
	before := nodes[1].r.step
	if !nodes[1].r.processOne() || nodes[1].r.step != before+1 {
		t.Fatal("original internal-first self delivery changed")
	}
	current := nodes[1].r.receiveContext.Load()
	if current == nil || !nodes[1].r.receiveCache.Known(current.scope, uint64(codec.CodePrepare), original[0]) {
		t.Fatal("normal own ACCEPT did not register the key")
	}
	if !nodes[1].r.processOne() || nodes[1].r.step != before+1 {
		t.Fatal("known honest relay invented another core step")
	}
	known := 0
	for _, event := range traces[1].snapshot() {
		if event.Action == transport.ReceiveCheckPrepare && event.Decision == transport.ReceiveKnown {
			known++
		}
	}
	if known != 1 || nodes[1].r.Vars().State != consensus.Preprepared {
		t.Fatal("normal queued relay did not exercise exactly one known-at-dispatch decision", known, nodes[1].r.Vars().State)
	}
	for i, n := range nodes {
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		if err := writers[i].Close(); err != nil {
			t.Fatal(err)
		}
		closed[i] = true
	}
	records, err := journal.ReadAll(nodes[1].jfs, "/receive-dispatch")
	if err != nil {
		t.Fatal(err)
	}
	bounds := receiveDispositionBounds()
	check, err := journal.CheckReceiveDispatchSources(records, bounds)
	if err != nil || check.Status != "consistent" || check.DiscardedKnown != 1 || check.SelfRegistrations == 0 || check.RetainedPreparations != 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
		t.Fatal("independent honest relay source", check, err)
	}
	for _, legacy := range []string{"inbox", "selection"} {
		if legacy == "inbox" {
			c, e := journal.CheckInboxSources(records, bounds.Selections.Inbox)
			if e != nil || c.Status != "unavailable" || c.Reason != "inbox_dispatch_deduplicated" {
				t.Fatal(c, e)
			}
		} else {
			c, e := journal.CheckInputSelections(records, bounds.Selections)
			if e != nil || c.Status != "unavailable" || c.Reason != "inbox_inbox_dispatch_deduplicated" {
				t.Fatal(c, e)
			}
		}
	}

	// All actors and logs are stopped before contradictory copies are inspected.
	// These changes never enter a node, transport, signer, clock or timer.
	for _, mode := range []string{"lookup", "namespace", "scope", "context", "decision", "selection", "inbox", "internal", "input", "completion", "discard_step", "discard_input", "duplicate", "missing", "version", "unavailable", "operations", "bytes", "gap"} {
		t.Run(mode, func(t *testing.T) {
			copied := slices.Clone(records)
			limits := bounds
			want := "inconsistent"
			switch mode {
			case "operations":
				limits.Operations = 1
				want = "unavailable"
			case "bytes":
				limits.Bytes = 1
				want = "unavailable"
			case "gap":
				copied = append(copied, journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindReceiveDispatch), Count: 1}}}})
				want = "unavailable"
			default:
				changed := false
				for i, rec := range copied {
					r, ok := rec.Body.(*journal.ReceiveDispatchRec)
					if !ok {
						continue
					}
					discardOnly := mode == "discard_step" || mode == "discard_input" || mode == "completion"
					if discardOnly && r.Action != "discard" || !discardOnly && r.Action != "prepare" {
						continue
					}
					c := *r
					c.Input = bytes.Clone(r.Input)
					switch mode {
					case "lookup":
						c.Source.Sequence = ^uint64(0)
						want = "unavailable"
					case "namespace":
						c.Source.WriterRun = "different-original-writer"
						want = "unavailable"
					case "scope":
						c.Scope++
					case "context":
						c.ContextHash[0] ^= 1
					case "decision":
						if c.Decision == uint64(transport.ReceiveReserved) {
							c.Decision = uint64(transport.ReceiveKnown)
						} else {
							c.Decision = uint64(transport.ReceiveReserved)
						}
					case "selection":
						c.Selection = ^uint64(0)
						want = "unavailable"
					case "inbox":
						c.InboxRequest++
					case "internal":
						c.InternalRequest++
					case "input":
						c.Input[len(c.Input)-1] ^= 1
					case "completion":
						c.Request++
					case "discard_step":
						c.Step = 1
					case "discard_input":
						c.Input[len(c.Input)-1] ^= 1
					case "duplicate":
						copied = append(copied, rec)
					case "missing":
						copied = append(copied[:i], copied[i+1:]...)
						want = "unavailable"
					case "version":
						c.Version++
						want = "unavailable"
					case "unavailable":
						c.Unavailable = "replayed_prefix"
						want = "unavailable"
					}
					if mode != "duplicate" && mode != "missing" {
						copied[i].Body = &c
					}
					changed = true
					break
				}
				if !changed {
					t.Fatal("offline contradiction target missing", mode)
				}
			}
			got, e := journal.CheckReceiveDispatchSources(copied, limits)
			if got.Status != want || (want == "inconsistent") != (e != nil) {
				t.Fatal("offline contradictory source accepted or misclassified", mode, got, e)
			}
		})
	}
}

// Each callback owns a detached value and only appends diagnostic evidence.
type receiveDispositionRecorder struct{ writer journal.Writer }

func (o *receiveDispositionRecorder) CaptureRun() string {
	return o.writer.(interface{ CaptureRun() string }).CaptureRun()
}
func (o *receiveDispositionRecorder) ObserveCoreStep(r CoreStepObservation) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveTimerSource(r journal.TimerRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveAppQueueSource(r journal.AppQueueRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveFinalizeSource(r journal.FinalizeRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveInboxSource(r journal.InboxRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveInternalSource(r journal.InternalRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveInputSelection(r journal.SelectionRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *receiveDispositionRecorder) ObserveReceiveDispatch(r journal.ReceiveDispatchRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func receiveDispositionBounds() journal.ReceiveDispatchLimits {
	core := journal.CoreSourceLimits{Records: 200000, Runs: 8, Steps: 10000, Environments: 10000, Outputs: 100000, Bytes: 256 << 20}
	return journal.ReceiveDispatchLimits{Receive: journal.ReceiveSourceLimits{Core: core, Receive: journal.ReceiveCacheCheckLimits{Records: 200000, Ledgers: 8, Reordered: 64}, Frames: 10000, Captures: 10000, Sessions: 256}, Selections: journal.SelectionLimits{Internal: journal.InternalLimits{Core: core, Operations: 20000, Entries: 10000, Outputs: 100000, Bytes: 64 << 20}, App: journal.AppQueueLimits{Core: core, Operations: 20000, Entries: 10000, Bytes: 64 << 20}, Timer: journal.TimerSourceLimits{Core: core, Operations: 20000, Bindings: 20000, Bytes: 64 << 20}, Inbox: journal.InboxLimits{Core: core, Operations: 20000, Entries: 10000, Peers: 256, Frames: 10000, Bytes: 64 << 20}, Operations: 20000, Sources: 100000, Bytes: 64 << 20}, Operations: 20000, Bytes: 64 << 20}
}
