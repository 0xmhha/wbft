package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func writeQueueScenario(t *testing.T, mixed bool) Scenario {
	t.Helper()
	keys := testValidators(t, 4)
	sc := Scenario{Validators: keys, Seed: 61, DefaultLink: Link{Delay: []time.Duration{7 * time.Millisecond}}, Until: Stop{Height: 8, Duration: time.Minute}}
	for i := range keys {
		n := DefaultNode()
		if !mixed || i%2 == 0 {
			n.WriteQueue = &WriteQueueProfile{Waiting: 64, WriteTime: 3 * time.Millisecond}
		}
		sc.Nodes = append(sc.Nodes, n)
	}
	return sc
}

func TestWriteQueueNormalProgressAndRestart(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		sc := writeQueueScenario(t, mixed)
		addr := addrOf(sc.Validators[3])
		sc.Schedule = []NodeEvent{{At: 2 * time.Second, Node: addr, Action: ActionStop}, {At: 4 * time.Second, Node: addr, Action: ActionRestart}}
		res, err := Run(context.Background(), sc, Output{})
		if err != nil || len(res.Violations) != 0 || res.Crashes != 0 {
			t.Fatal("normal write-service simulation", mixed, err, res)
		}
		for _, h := range res.Heads {
			if h < 8 {
				t.Fatal("normal progress incomplete", mixed, res.Heads)
			}
		}
		declarations := 0
		for _, raw := range res.Events {
			for _, line := range bytes.Split(raw, []byte("\n")) {
				if len(line) == 0 {
					continue
				}
				var m map[string]json.RawMessage
				if err := json.Unmarshal(line, &m); err != nil {
					t.Fatal(err)
				}
				if _, ok := m["write_queue_model"]; ok {
					declarations++
				}
			}
		}
		want := 5
		if mixed {
			want = 2
		}
		if declarations != want {
			t.Fatal("optional model declaration or normal restart missing", mixed, declarations)
		}
		if sc.Nodes[0].WriteQueue.Waiting != 64 {
			t.Fatal("scenario model modified")
		}
	}
}

func normalWriteFrame(t *testing.T, n *node) []byte {
	t.Helper()
	key, err := ecdsa.PrivateKeyFromBytes(n.v.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(1)}}
	signing, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := consensus.Recover(m.Code, raw, nil)
	if err != nil || checked.Source != n.v.address {
		t.Fatal("normal original signature", err)
	}
	return raw
}

func writeQueueNodes(t *testing.T) *simulation {
	t.Helper()
	sc := writeQueueScenario(t, false)
	sc.Until.Height = 0
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	for _, n := range s.nodes {
		n.start()
		t.Cleanup(n.stop)
		if !n.alive || n.r == nil {
			t.Fatal("normal node start", s.viol)
		}
	}
	return s
}

func TestWriteQueueJournalFollowsCompletionBeforeArrival(t *testing.T) {
	s := writeQueueNodes(t)
	a, b := s.nodes[0], s.nodes[1]
	r := a.writes.route(b)
	peer := r.q.WritePeers()[0]
	raw, code := normalWriteFrame(t, a), uint64(codec.CodeRoundChange)
	receipts := 0
	if a.writes.SendWrite(peer, code, raw, transport.SendAttempt{}, func(got transport.WriteReceipt) {
		receipts++
		if got.Target != peer || got.Result != transport.LocalWriteOK || s.l.c.Mono() != 3*time.Millisecond {
			t.Fatal("original local completion", got, s.l.c.Mono())
		}
	}) != transport.Queued {
		t.Fatal("queue admission")
	}
	count := func(n *node, dir string) int {
		t.Helper()
		if err := n.jw.Sync(); err != nil {
			t.Fatal(err)
		}
		recs, err := journal.ReadAll(n.fs, journalDir)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, rec := range recs {
			if msg, ok := rec.Body.(*journal.MsgRec); ok && msg.Dir == dir && bytes.Equal(msg.Payload, raw) {
				total++
			}
		}
		return total
	}
	s.l.runAt(2 * time.Millisecond)
	if receipts != 0 || count(a, journal.Out) != 0 || count(b, journal.In) != 0 {
		t.Fatal("admission became completion or read")
	}
	s.l.runAt(3 * time.Millisecond)
	if receipts != 1 || count(a, journal.Out) != 1 || count(b, journal.In) != 0 {
		t.Fatal("local completion journal or independent link delay")
	}
	s.l.runAt(10 * time.Millisecond)
	if count(b, journal.In) != 1 {
		t.Fatal("remote read not after write service and link delay")
	}
}

func TestWriteQueueOldArrivalCannotUseReplacementRoute(t *testing.T) {
	s := writeQueueNodes(t)
	a, b := s.nodes[0], s.nodes[1]
	old := a.writes.route(b)
	peer := old.q.WritePeers()[0]
	raw, code := normalWriteFrame(t, a), uint64(codec.CodeRoundChange)
	got := 0
	if a.writes.SendWrite(peer, code, raw, transport.SendAttempt{}, func(transport.WriteReceipt) { got++ }) != transport.Queued {
		t.Fatal("queue admission")
	}
	s.l.runAt(3 * time.Millisecond)
	before := b.capture
	a.writes.closePeer(b)
	replacement := a.writes.route(b)
	if replacement.q.WritePeers()[0].Session == peer.Session {
		t.Fatal("route replacement reused old stream")
	}
	s.l.runAt(10 * time.Millisecond)
	if b.capture != before || got != 1 {
		t.Fatal("old delivery used current route or issued a second receipt")
	}
	// A normal peer stop cancels only its pending original stream requests.
	result := transport.LocalWriteResult(0)
	a.writes.SendWrite(replacement.q.WritePeers()[0], code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) { result = r.Result })
	b.stop()
	if result != transport.LocalWriteCancelled || len(replacement.q.WritePeers()) != 0 {
		t.Fatal("peer stop did not cancel original queue", result)
	}
	b.start()
	if fresh := a.writes.route(b); fresh == replacement || fresh.inc == replacement.inc {
		t.Fatal("normal restart transferred an old queue")
	}
}

func TestWriteQueueNormalDisconnectAndStoppingCallback(t *testing.T) {
	s := writeQueueNodes(t)
	a, b, c := s.nodes[0], s.nodes[1], s.nodes[2]
	raw, code := normalWriteFrame(t, a), uint64(codec.CodeRoundChange)
	old := a.writes.route(b).q.WritePeers()[0]
	receipts := 0
	a.writes.SendWrite(old, code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) {
		receipts++
		if r.Result != transport.LocalWriteCancelled {
			t.Fatal("normal disconnect did not cancel pending write")
		}
	})
	a.writes.Disconnect(b.v.address, "normal_close")
	if receipts != 1 || a.writes.route(b) != nil || b.writes.route(a) != nil || len(s.sc.Partitions) != 0 {
		t.Fatal("ordinary disconnect did not close both original queues")
	}
	s.l.runAt(time.Second)
	fresh := a.writes.route(b).q.WritePeers()[0]
	if fresh.Session == old.Session {
		t.Fatal("normal reconnect reused stream")
	}
	a.writes.SendWrite(fresh, code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) {
		receipts++
		if r.Result != transport.LocalWriteCancelled || a.writes.route(c) != nil {
			t.Fatal("stopping callback revived outbound work")
		}
	})
	a.stop()
	if receipts != 2 || len(a.writes.WritePeers()) != 0 {
		t.Fatal("stopped adapter retained pending work")
	}
}

func TestWriteQueueProfileValidationAndOwnership(t *testing.T) {
	sc := writeQueueScenario(t, false)
	for _, p := range []*WriteQueueProfile{{}, {Waiting: 65537}, {Waiting: 1, WriteTime: -1}, {Waiting: 1, WriteTime: sc.Until.Duration + 1}} {
		if _, err := cloneWriteQueue(p, sc); err == nil {
			t.Fatal("invalid queue declaration accepted", p)
		}
	}
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	sc.Nodes[0].WriteQueue.Waiting = 1
	if s.nodes[0].spec.WriteQueue.Waiting != 64 {
		t.Fatal("simulation retained caller's mutable profile")
	}
	var legacy transport.Transport = &adapter{}
	if _, ok := legacy.(transport.WriteSender); ok {
		t.Fatal("default adapter gained completion capability")
	}
}
