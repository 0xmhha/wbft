package stepdriver

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestDeferredReceiptRequiresOriginalWriterClock(t *testing.T) {
	f := newFixture(t)
	raw, err := hex.DecodeString(f.sign(1, &codec.Message{Code: codec.CodeRoundChange, View: v(11, 1)}, nil, nil)[2:])
	if err != nil {
		t.Fatal(err)
	}
	m := consensus.Message{Code: codec.CodeRoundChange, Payload: raw, Peer: f.addrs[1], RecvMono: 23}
	body, err := inputlog.EncodeDeferredMessage(m, inputlog.CaptureOrigin{Run: "first-writer", Capture: 17})
	if err != nil {
		t.Fatal(err)
	}
	fs := fsys.NewMem()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/j", Synchronous: true}, journal.Identity{Run: "first-writer"})
	if err != nil {
		t.Fatal(err)
	}
	w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 2, Addr: m.Peer, Event: "attached"}})
	w.Put(journal.Record{Body: &journal.MsgRec{Capture: 17, Dir: journal.In, PeerIdx: 2, Code: uint64(m.Code), Payload: raw, Mono: 9, Offer: transport.OfferQueued}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := journal.OpenReader(fs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	step := &journal.StepRec{InputKind: inputlog.KindDeferredMessage, Input: body, Via: "peer"}
	if mono, err := externalReceipt(r, "first-writer", step); err != nil || mono != 9 {
		t.Fatalf("same writer: %d %v", mono, err)
	}
	if _, err := externalReceipt(r, "second-writer", step); !errors.Is(err, ErrTraceScheduleReservation) {
		t.Fatalf("cross-writer clock was invented: %v", err)
	}
	e, err := deferredEvidence(r, body)
	if err != nil || e.Status != "verified" || e.Origin.Run != "first-writer" {
		t.Fatalf("physical evidence lost: %+v %v", e, err)
	}
	// A verified physical source in another run is useful evidence, but does
	// not make its receipt time comparable to the new writer's clock.
	if _, err := deferredReceipt(r, "second-writer", body); !errors.Is(err, ErrTraceScheduleReservation) {
		t.Fatal(err)
	}
}
