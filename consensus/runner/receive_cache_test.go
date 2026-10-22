package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestReceiveCacheActualCoreAcceptanceAndNormalRestart(t *testing.T) {
	k := newKeys(t, 4)
	var referenceVars, referenceRestart *consensus.Vars
	var referenceSent []sent
	var referenceWAL []wal.Record
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, k, 1)
		n.noJournal = true
		if enabled {
			n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true}
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
