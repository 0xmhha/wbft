package runner

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// Use the existing normal graceful-restart fixture, retaining its original
// signed own messages and WAL. The first scheduler turn after installation
// processes an ordinary restored own message before another live core step.
func TestRestoredReceiveDispatchFirstLivePreparation(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 0)
	n.noJournal = true
	n.chain.head.Time = uint64(n.clock.Now().Unix()) - 1
	limits := transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	writer, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/restored-dispatch", Synchronous: true}, journal.Identity{Run: "normal-restored-dispatch", Self: n.opts.Self, Mode: "diagnostic", Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit), TimerTrace: journal.TimerTraceVersion, CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}}})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if closed {
			return
		}
		if n.r != nil {
			if err := n.r.Close(); err != nil {
				t.Error(err)
			}
		}
		if n.log != nil {
			if err := n.log.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	o := &restoreRecorder{receiveDispositionRecorder{writer: writer}}
	n.walReadSources, n.coreSteps, n.timerSources = o, o, o
	n.walReadSourceLimits = wal.ReadSourceLimits{Frames: 1024, Bytes: 8 << 20}
	n.appQueueSources, n.finalizeSources, n.inboxSources = o, o, o
	n.internalSources, n.selectionSources, n.receiveDispatchSources = o, o, o
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 32, PerPeer: 8, KeyWithCode: true, Trace: &runnerReceiveTransitions{clock: n.clock, writer: writer}}
	n.boot()
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	b.Header.Time = uint64(n.clock.Now().Unix())
	n.r.Submit(b)
	for i := range 2 {
		if !n.r.processOne() {
			t.Fatal("normal builder or own proposal missing", i)
		}
	}
	if n.r.Halted() != nil || len(n.r.internal) == 0 || len(n.net.own(codec.CodePreprepare)) != 1 || len(n.net.own(codec.CodePrepare)) != 1 {
		t.Fatal("normal proposal did not retain an original own vote", n.r.Halted())
	}
	// Supply the public receiver checker with one genuine external registration.
	// The second honest actor receives this actor's actual proposal and sends
	// its ordinary PREPARE back; no payload is constructed or re-signed here.
	peer := newTNode(t, k, 1)
	peer.noJournal = true
	peer.chain.head.Time = n.chain.head.Time
	peer.boot()
	peerClosed := false
	t.Cleanup(func() {
		if !peerClosed {
			if err := peer.r.Close(); err != nil {
				t.Error(err)
			}
			if err := peer.log.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	sentTo := func(actor *tnode, code codec.Code, payload []byte, target int) bool {
		for _, sent := range actor.net.sent {
			if sent.code != uint64(code) || !bytes.Equal(sent.payload, payload) {
				continue
			}
			for _, address := range sent.peers {
				if address == k.addrs[target] {
					return true
				}
			}
		}
		return false
	}
	proposal := n.net.own(codec.CodePreprepare)[0]
	if !sentTo(n, codec.CodePreprepare, proposal, 1) {
		t.Fatal("proposal was not actually sent to the honest peer")
	}
	peer.deliver(0, codec.CodePreprepare, proposal)
	votes := peer.net.own(codec.CodePrepare)
	if len(votes) != 1 {
		t.Fatal("honest peer did not emit its original vote", len(votes))
	}
	if !sentTo(peer, codec.CodePrepare, votes[0], 0) {
		t.Fatal("vote was not actually sent to the original proposer")
	}
	stream := transport.NewWriteSession()
	stream.BindObservationRun("normal-restored-dispatch")
	writer.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: k.addrs[1], Event: "attached"}})
	writer.Put(journal.Record{Body: &journal.SessionRec{Session: &journal.SessionRef{Run: stream.ObservationRun(), Ordinal: stream.ObservationID()}, Peer: k.addrs[1], Event: journal.SessionObserved, Active: true, Mono: n.clock.Mono(), WallNs: n.clock.Now().UnixNano()}})
	in := transportInbound(k, 1, codec.CodePrepare, votes[0], n.clock.now)
	in.Capture, in.Stream = 1, stream
	in.Origin = transport.ReceiveOrigin{WriterRun: "normal-restored-dispatch", CaptureID: 1}
	writer.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Session: &journal.SessionRef{Run: stream.ObservationRun(), Ordinal: stream.ObservationID()}, Capture: 1, Code: uint64(codec.CodePrepare), WireCode: uint64(codec.CodePrepare), Payload: append([]byte(nil), votes[0]...), Size: uint64(len(votes[0])), Mono: n.clock.Mono(), WallNs: n.clock.Now().UnixNano(), DedupKey: codec.DedupKey(votes[0]), Engine: "running", Offer: "queued"}})
	if !n.r.Receiver().Offer(in) || !n.r.inbox.checkOne(true) {
		t.Fatal("ordinary genuine peer vote was not checked")
	}
	n.r.Pump()
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	if !n.r.replay.Replayed || len(n.r.internal) == 0 {
		t.Fatal("normal WAL installation lost its original own messages")
	}
	installed := n.r.step
	if !n.r.processOne() || n.r.step != installed+1 {
		t.Fatal("first ordinary restored message did not reach the core", installed, n.r.step)
	}
	n.r.Pump()
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.log.Close(); err != nil {
		t.Fatal(err)
	}
	peerClosed = true
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	rows, err := journal.ReadAll(n.jfs, "/restored-dispatch")
	if err != nil {
		t.Fatal(err)
	}
	var engine, preparations, dispatches uint64
	anchor, first, prepared := -1, -1, -1
	for index, row := range rows {
		if r, ok := row.Body.(*journal.RestoreRec); ok && r.Installed == 1 && r.Replayed == 1 {
			if r.Steps != installed {
				t.Fatal("observed installation step changed", r.Steps, installed)
			}
			engine, anchor = r.EngineRun, index
		}
	}
	for index, row := range rows {
		switch r := row.Body.(type) {
		case *journal.CoreStepRec:
			if r.EngineRun == engine && r.Step == installed {
				t.Fatal("installation was represented as a live core step")
			}
			if r.EngineRun == engine && r.Step == installed+1 {
				first = index
			}
		case *journal.ReceiveDispatchRec:
			if r.Action == "prepare" {
				preparations++
			} else if r.Action == "dispatch" {
				dispatches++
			}
			if r.EngineRun == engine && r.BeforeStep == installed && r.Action == "prepare" {
				if r.Via != "internal" || r.InternalRequest == 0 || r.Unavailable != "replayed_prefix" {
					t.Fatal("original restored own preparation identity changed")
				}
				prepared = index
			}
		}
	}
	if engine == 0 || anchor < 0 || prepared <= anchor || first <= prepared {
		t.Fatal("normal installed-before-first-live boundary missing", engine, anchor, prepared, first)
	}
	result, err := journal.CheckRestoredReceiveDispatchSources(rows, receiveDispositionBounds())
	if err != nil || result.Status != "consistent" || result.Reason != "" || result.Prepared != preparations || result.Dispatched != dispatches || preparations == 0 || dispatches == 0 || result.RetainedPreparations != 0 || result.PhysicalStatus != "unavailable" || result.ScheduleStatus != "unavailable" {
		t.Fatal("normal first live preparation did not preserve its verified installation context", result, err)
	}
	ordinary, err := journal.CheckReceiveDispatchSources(rows, receiveDispositionBounds())
	if err != nil || ordinary.Status != "unavailable" {
		t.Fatal("ordinary reader accepted a restored prefix", ordinary, err)
	}
	// These copies change only detached observer metadata after both actors
	// stopped. The original messages, signatures and WAL are never modified.
	for _, test := range []struct {
		name, reason string
		change       func([]journal.Record) []journal.Record
	}{
		{"prepare_after_first_live", "preparation_outside_restored_boundary", func(copied []journal.Record) []journal.Record {
			prepare := copied[prepared]
			copy(copied[prepared:first], copied[prepared+1:first+1])
			copied[first] = prepare
			return copied
		}},
		{"prepare_after_entry_time", "preparation_outside_restored_boundary", func(copied []journal.Record) []journal.Record {
			prepare := *copied[prepared].Body.(*journal.ReceiveDispatchRec)
			prepare.Mono = uint64(copied[first].Body.(*journal.CoreStepRec).Entry.Mono) + 1
			copied[prepared].Body = &prepare
			return copied
		}},
		{"snapshot_digest_changed", "preparation_snapshot_changed", func(copied []journal.Record) []journal.Record {
			prepare := *copied[prepared].Body.(*journal.ReceiveDispatchRec)
			prepare.ContextHash[0] ^= 1
			copied[prepared].Body = &prepare
			return copied
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copied := test.change(append([]journal.Record(nil), rows...))
			got, e := journal.CheckRestoredReceiveDispatchSources(copied, receiveDispositionBounds())
			if e == nil || got.Status != "inconsistent" || got.Reason != test.reason {
				t.Fatal("detached preparation contradiction was not rejected", got, e)
			}
		})
	}
	t.Logf("normal_restored_dispatch engine=%d installed_step=%d anchor_index=%d prepare_index=%d first_live_index=%d first_live_step=%d reader_status=%s reader_reason=%s synthetic_live_step=false original_own_message=true", engine, installed, anchor, prepared, first, installed+1, result.Status, result.Reason)
}
