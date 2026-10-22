package runner

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestNextHeightJournalKeepsOriginAcrossWriterRestart(t *testing.T) {
	k := newKeys(t, 4)
	n := newNextHeightNode(t, k, k.vs, types.HeightFromUint64(10), &NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}, false)
	n.close()
	fs := fsys.NewMem()
	open := func(run string) {
		t.Helper()
		w, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Run: run})
		if err != nil {
			t.Fatal(err)
		}
		n.jw = w
		n.boot()
	}
	open("first-writer")
	raw := k.sign(t, 1, &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(1)}}, nil)
	n.jw.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: k.addrs[1], Event: "attached"}})
	n.jw.Put(journal.Record{Body: &journal.MsgRec{Capture: 17, Dir: journal.In, PeerIdx: 2, Code: uint64(codec.CodeRoundChange), Payload: raw, Mono: 9, Offer: transport.OfferQueued}})
	if !n.r.Receiver().Offer(transport.Inbound{Code: uint64(codec.CodeRoundChange), Payload: raw, Peer: k.addrs[1], RecvMono: 23, Capture: 17}) {
		t.Fatal("normal offer refused")
	}
	n.r.Pump()
	n.close()
	if err := n.jw.Close(); err != nil {
		t.Fatal(err)
	}
	open("second-writer")
	head := block(t, 10, 1, k.addrs[3], codec.BlockHash(n.chain.Head())).Header
	n.advance(head, k.vs, true)
	if entries, size := n.r.NextHeightUsage(); entries != 0 || size != 0 {
		t.Fatal("release retained reservation")
	}
	n.close()
	if err := n.jw.Close(); err != nil {
		t.Fatal(err)
	}
	// A second process replay must journal the same original source again.
	open("third-writer")
	n.r.Pump()
	n.close()
	if err := n.jw.Close(); err != nil {
		t.Fatal(err)
	}
	n.jw = nil
	records, err := journal.ReadAll(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	r, err := journal.OpenReader(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	writers := map[string]int{}
	writer := ""
	for _, rec := range records {
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			writer = b.Run
		case *journal.StepRec:
			if b.InputKind != inputlog.KindDeferredMessage {
				continue
			}
			m, e, err := journal.InspectDeferred(r, b.Input)
			if err != nil || e.Status != "verified" || e.Origin.Run != "first-writer" || e.Origin.Capture != 17 || e.ReceiptMono == nil || *e.ReceiptMono != "9" || !bytes.Equal(m.Payload, raw) || m.Peer != k.addrs[1] || m.RecvMono != time.Duration(23) {
				t.Fatalf("source lost in %s: %+v %+v %v", writer, m, e, err)
			}
			writers[writer]++
		}
	}
	if writers["second-writer"] != 1 || writers["third-writer"] != 1 {
		t.Fatalf("release/replay counts: %v", writers)
	}
}
