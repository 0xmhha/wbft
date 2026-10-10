package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
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
// times, a frame whose payload was not kept keeps its size, and sends the
// transport did not attempt are recorded as not_attached or error.
func TestFrameRecorder(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0x10)
	p1, p2, p3 := types.Address{1}, types.Address{2}, types.Address{3}
	rec.Attached(p2, "10.0.0.2:1")
	rec.Received(p2, 0x12, 1, []byte("a"), transport.OfferQueued)
	rec.Received(p2, 0x13, 20<<20, nil, transport.OfferFrameDisconnect) // too large: no payload kept
	rec.Wrote(p1, 0x13, []byte("b"), transport.WriteOK)
	rec.Closed(p2, "read")
	tr := recordedTransport{Transport: resultTransport{res: []transport.SendResult{transport.Queued, transport.NotAttached, transport.QueueFull}}, rec: rec}
	tr.Send([]types.Address{p1, p2, p3}, 0x14, []byte("c"))

	want := []string{"peer 1 attached", "msg in 1 0x22 queued size 0", "msg in 1 0x23 frame_disconnect size 20971520", "msg out 2 0x23 ok", "peer 1 closed", "msg out 1 0x24 not_attached", "msg out 3 0x24 error"}
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
			if b.Dir == journal.In {
				got += fmt.Sprintf(" size %d", b.Size)
			}
			key := codec.DedupKey(b.Payload)
			if b.Size > 0 {
				key = types.Hash{} // payload not kept
			}
			if b.DedupKey != key || b.Mono != 5*time.Second || b.WallNs != 10e9 {
				t.Fatalf("record %d: %+v", i, b)
			}
		}
		if got != want[i] {
			t.Fatalf("record %d: %q, want %q", i, got, want[i])
		}
	}
}

// TestFrameRecorderCauses: the cause of a send reaches the msg record of
// each write the transport reports and of each send it did not attempt; a
// write without a known cause has none; a suppressed send becomes a
// suppressed record.
func TestFrameRecorderCauses(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	p1, p2, p3 := types.Address{1}, types.Address{2}, types.Address{3}
	payload := []byte{0xc1, 0x09}
	tr := recordedTransport{Transport: resultTransport{res: []transport.SendResult{transport.Queued, transport.NotAttached}}, rec: rec}
	tr.SendCause([]types.Address{p1, p2}, 0x14, payload, event.CauseRelay)
	rec.Wrote(p1, 0x14, payload, transport.WriteOK)
	rec.Wrote(p1, 0x14, payload, transport.WriteOK) // a second write of the same bytes: cause already used
	tr.Suppressed(p3, 0x14, payload, event.CauseRetry, transport.SuppressRecentCache)

	var got []string
	for _, r := range jw.recs {
		switch b := r.Body.(type) {
		case *journal.MsgRec:
			got = append(got, fmt.Sprintf("msg %d %s %q", b.PeerIdx, b.Write, b.Cause))
		case *journal.SuppressedRec:
			got = append(got, fmt.Sprintf("suppressed %d %s %s %v", b.PeerIdx, b.Cause, b.Reason, b.DedupKey == codec.DedupKey(payload)))
		}
	}
	want := []string{`msg 1 not_attached "relay"`, `msg 2 ok "relay"`, `msg 2 ok ""`, "suppressed 3 retry peer_recent_cache true"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("records %q, want %q", got, want)
	}
}

// TestFrameRecorderEngine records the engine state with each received
// frame.
func TestFrameRecorderEngine(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	state := "syncing"
	rec.engine = func() string { return state }
	rec.Received(types.Address{1}, 0x12, 1, []byte{1}, transport.OfferQueued)
	state = "running"
	rec.Received(types.Address{1}, 0x13, 1, []byte{2}, transport.OfferQueued)
	rec.Wrote(types.Address{1}, 0x13, []byte{2}, transport.WriteOK)
	var got []string
	for _, r := range jw.recs {
		m := r.Body.(*journal.MsgRec)
		got = append(got, m.Dir+":"+m.Engine)
	}
	if want := []string{"in:syncing", "in:running", "out:"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("engine states %q, want %q", got, want)
	}
}

// TestFrameRecorderDedup puts the dedup cache hits on the received frame of
// the peer they were reported for, once: a frame the node did not check has
// none.
func TestFrameRecorderDedup(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	p1, p2 := types.Address{1}, types.Address{2}
	rec.inbound(p1, true, false)
	rec.Received(p2, 0x13, 1, []byte{1}, transport.OfferQueueFull)
	rec.Received(p1, 0x13, 1, []byte{1}, transport.OfferQueued)
	rec.Received(p1, 0x13, 1, []byte{2}, transport.OfferQueueFull)
	var got []string
	for _, r := range jw.recs {
		got = append(got, fmt.Sprint(r.Body.(*journal.MsgRec).Dedup))
	}
	if want := []string{"<nil>", "&{true false}", "<nil>"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dedup %q, want %q", got, want)
	}
}

// TestEngineState follows the runner and the application's
// synchronisation.
func TestEngineState(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, false, nil)
	if s := n.engineState(); s != "running" {
		t.Fatalf("started node: %s", s)
	}
	if err := n.Runner().Stop(); err != nil {
		t.Fatal(err)
	}
	if s := n.engineState(); s != "stopped" {
		t.Fatalf("stopped engine: %s", s)
	}
	n.syncMu.Lock()
	n.syncLatest = &app.SyncState{Syncing: true}
	n.syncMu.Unlock()
	if s := n.engineState(); s != "syncing" {
		t.Fatalf("stopped engine while synchronising: %s", s)
	}
	stop(t, n)
}
