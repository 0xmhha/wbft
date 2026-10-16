package node

import (
	"github.com/0xmhha/wbft/chain/validator"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestLegacyOverlappingWritesDoNotClaimLatestCause(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	peer := types.Address{7}
	payload := []byte{0xc0}
	tr := recordedTransport{Transport: resultTransport{res: []transport.SendResult{transport.Queued}}, rec: rec}
	tr.SendCause([]types.Address{peer}, 0x13, payload, event.CauseRetry)
	tr.SendCause([]types.Address{peer}, 0x13, payload, event.CauseRelay)
	// A legacy callback carries neither queue identity nor observer ownership.
	rec.Wrote(peer, 0x13, payload, transport.WriteOK)
	got := jw.recs[len(jw.recs)-1].Body.(*journal.MsgRec)
	if got.Cause != "" {
		t.Fatalf("ambiguous legacy write claimed latest cause %q", got.Cause)
	}
}

// queuedAttemptTransport deliberately permits writes to finish out of order.
type queuedAttemptTransport struct {
	transport.Transport
	attempts []transport.SendAttempt
	results  []transport.SendResult
}

func (q *queuedAttemptTransport) SendAttempt(_ []types.Address, _ uint64, _ []byte, a transport.SendAttempt) []transport.SendResult {
	q.attempts = append(q.attempts, a)
	return q.results
}

func TestQueuedWriteAttemptsKeepTheirOwnCauses(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	peer := types.Address{7}
	payload := []byte{0xc0}
	q := &queuedAttemptTransport{results: []transport.SendResult{transport.Queued}}
	tr := recordedTransport{Transport: q, rec: rec}
	tr.SendCause([]types.Address{peer}, 0x13, payload, event.CauseRetry)
	tr.SendCause([]types.Address{peer}, 0x13, payload, event.CauseRelay)
	if len(q.attempts) != 2 || q.attempts[0].Sequence == 0 || q.attempts[0].Sequence == q.attempts[1].Sequence {
		t.Fatal("attempt identity missing")
	}
	// The second send completes first; no FIFO or peer/key lookup is valid.
	rec.WroteAttempt(peer, 0x13, payload, transport.WriteOK, q.attempts[1], nil)
	rec.WroteAttempt(peer, 0x13, payload, transport.WriteError, q.attempts[0], nil)
	for i, index := range []int{1, 0} {
		m := jw.recs[i].Body.(*journal.MsgRec)
		if m.Cause != q.attempts[index].Cause || m.Attempt == nil || m.Attempt.Sequence != q.attempts[index].Sequence {
			t.Fatalf("write %d lost its attempt: %+v", i, m)
		}
	}
	// An old recording lifetime must not consume a new legacy expectation.
	next := newFrameRecorder(jw, fixedClock{}, 0)
	next.expect([]types.Address{peer}, rec.msg(journal.Out, peer, 0x13, payload).DedupKey, event.CauseBroadcast)
	next.WroteAttempt(peer, 0x13, payload, transport.WriteOK, q.attempts[0], nil)
	m := jw.recs[len(jw.recs)-1].Body.(*journal.MsgRec)
	if m.Attempt != nil || m.Cause != "" {
		t.Fatal("old queue acquired new recording cause", m)
	}
}

func TestAttemptQueueRejectionsKeepIdentity(t *testing.T) {
	for _, result := range []transport.SendResult{transport.NotAttached, transport.QueueFull} {
		jw := &memJournal{}
		rec := newFrameRecorder(jw, fixedClock{}, 0)
		q := &queuedAttemptTransport{results: []transport.SendResult{result}}
		tr := recordedTransport{Transport: q, rec: rec}
		tr.SendCause([]types.Address{{7}}, 0x13, []byte{0xc0}, event.CauseRetry)
		if len(jw.recs) != 1 {
			t.Fatal("missing or duplicate rejection", len(jw.recs))
		}
		m := jw.recs[0].Body.(*journal.MsgRec)
		want := transport.WriteError
		if result == transport.NotAttached {
			want = transport.WriteNotAttached
		}
		if m.Attempt == nil || m.Attempt.Sequence != q.attempts[0].Sequence || m.Write != want || m.Cause != event.CauseRetry || m.IO != nil {
			t.Fatal("rejection provenance lost", m)
		}
	}
}

type delayedCacheTransport struct {
	transport.Transport
	rec     *frameRecorder
	peer    types.Address
	entered chan transport.SendAttempt
	release chan struct{}
}

func (q *delayedCacheTransport) Peers() []transport.PeerInfo {
	return []transport.PeerInfo{{Addr: q.peer}}
}
func (q *delayedCacheTransport) SendAttempt(peers []types.Address, code uint64, payload []byte, a transport.SendAttempt) []transport.SendResult {
	q.entered <- a
	<-q.release
	q.rec.WroteAttempt(peers[0], code, payload, transport.WriteOK, a, nil)
	return []transport.SendResult{transport.Queued}
}

func TestCacheDecisionPrecedesDelayedWriteAndLaterSuppression(t *testing.T) {
	jw := &memJournal{}
	rec := newFrameRecorder(jw, fixedClock{}, 0)
	self, peer := types.Address{1}, types.Address{2}
	q := &delayedCacheTransport{rec: rec, peer: peer, entered: make(chan transport.SendAttempt, 1), release: make(chan struct{})}
	tr := recordedTransport{Transport: q, rec: rec}
	d, err := transport.NewDedup(tr, transport.DedupOptions{Self: self})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := validator.NewSet([]types.Address{self, peer}, [][]byte{nil, nil}, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0xc0}
	done := make(chan struct{})
	go func() { defer close(done); d.GossipTargets(vs, 0x13, payload, event.CauseRetry) }()
	var attempt transport.SendAttempt
	select {
	case attempt = <-q.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first send did not enter queue")
	}
	later := d.GossipTargets(vs, 0x13, payload, event.CauseRelay)
	if len(later.Targets) != 0 || len(later.Suppressed) != 1 || later.Suppressed[0] != peer {
		t.Fatal("cache semantics changed", later)
	}
	close(q.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("send did not complete")
	}
	var ops []*journal.CacheRec
	var suppressionIndex, frameIndex int
	var frame *journal.MsgRec
	for i, r := range jw.recs {
		switch b := r.Body.(type) {
		case *journal.CacheRec:
			ops = append(ops, b)
		case *journal.SuppressedRec:
			suppressionIndex = i
			if b.Cache != attempt.Cache || b.Operation != 2 {
				t.Fatal("suppression lost source", b)
			}
		case *journal.MsgRec:
			frameIndex = i
			frame = b
		}
	}
	if len(ops) != 3 || ops[0].Action != "begin" || ops[0].Mono != 0 || ops[0].WallNs != 0 || ops[1].Sequence != 1 || ops[2].Sequence != 2 || len(ops[1].Targets) != 1 || len(ops[2].Suppressed) != 1 {
		t.Fatal("cache operation snapshot incomplete", ops)
	}
	if attempt.Cache == 0 || attempt.Operation != 1 || frame == nil || frame.Attempt == nil || frame.Attempt.Cache != attempt.Cache || frame.Attempt.Operation != 1 || frame.Cause != event.CauseRetry || suppressionIndex >= frameIndex {
		t.Fatal("physical frame was bound to later suppression", attempt, frame)
	}
}
