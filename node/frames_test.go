package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type memJournal struct{ recs []journal.Record }

func (m *memJournal) Put(r journal.Record) { m.recs = append(m.recs, r) }
func (m *memJournal) Close() error         { return nil }

type fixedClock struct{}

func (fixedClock) Now() time.Time      { return time.Unix(10, 0) }
func (fixedClock) Mono() time.Duration { return 5 * time.Second }

// resultTransport answers every Send with fixed results.
type resultTransport struct {
	transport.Transport
	res []transport.SendResult
}

func (t resultTransport) Send([]types.Address, uint64, []byte) []transport.SendResult { return t.res }

// TestFrameRecorder: peers are numbered in the order they are first seen,
// msg records carry the wire code with the offset, the dedup key and the
// times, and sends the transport did not attempt are recorded as
// not_attached or error.
func TestFrameRecorder(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0x10)
	p1, p2, p3 := types.Address{1}, types.Address{2}, types.Address{3}
	rec.Attached(p2, "10.0.0.2:1")
	rec.Received(p2, 0x12, []byte("a"), transport.OfferQueued)
	rec.Wrote(p1, 0x13, []byte("b"), transport.WriteOK)
	rec.Closed(p2, "read")
	tr := recordedTransport{Transport: resultTransport{res: []transport.SendResult{transport.Queued, transport.NotAttached, transport.QueueFull}}, rec: rec}
	tr.Send([]types.Address{p1, p2, p3}, 0x14, []byte("c"))

	want := []string{"peer 1 attached", "msg in 1 0x22 queued", "msg out 2 0x23 ok", "peer 1 closed", "msg out 1 0x24 not_attached", "msg out 3 0x24 error"}
	if len(jw.recs) != len(want) {
		t.Fatalf("%d records, want %d", len(jw.recs), len(want))
	}
	for i, r := range jw.recs {
		var got string
		switch b := r.Body.(type) {
		case *journal.PeerRec:
			got = fmt.Sprintf("peer %d %s", b.PeerIdx, b.Event)
		case *journal.MsgRec:
			got = fmt.Sprintf("msg %s %d %#x %s%s", b.Dir, b.PeerIdx, b.WireCode, b.Offer, b.Write)
			if b.DedupKey != codec.DedupKey(b.Payload) || b.Mono != 5*time.Second || b.WallNs != 10e9 {
				t.Fatalf("record %d: %+v", i, b)
			}
		}
		if got != want[i] {
			t.Fatalf("record %d: %q, want %q", i, got, want[i])
		}
	}
}
