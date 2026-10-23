package writequeue

import (
	"bytes"
	"crypto/sha256"
	"math"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func normalMessage(t *testing.T, round uint64) []byte {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = 2
	key, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(1), Round: types.RoundFromUint64(round)}}
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
	verified, err := consensus.Recover(m.Code, raw, nil)
	if err != nil || verified.Source != ecdsa.Address(key) {
		t.Fatalf("normal signed fixture: %v", err)
	}
	return raw
}

func newQueue(t *testing.T, clock *manualclock.Clock, opt Options, arrive func(uint64, []byte)) *Queue {
	t.Helper()
	q, err := New(clock, types.Address{7}, opt, arrive)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestQueueAdmissionCompletionAndArrival(t *testing.T) {
	var clock manualclock.Clock
	var receipts []transport.WriteReceipt
	var receiptTimes, arrivalTimes []time.Duration
	raw := normalMessage(t, 1)
	original := bytes.Clone(raw)
	code := uint64(codec.CodeRoundChange)
	q := newQueue(t, &clock, Options{Waiting: 1, WriteTime: 5 * time.Millisecond, LinkTime: 20 * time.Millisecond}, func(gotCode uint64, got []byte) {
		if gotCode != code || !bytes.Equal(got, original) {
			t.Fatal("arrival changed original normal message")
		}
		arrivalTimes = append(arrivalTimes, clock.Mono())
	})
	done := func(r transport.WriteReceipt) {
		receipts = append(receipts, r)
		receiptTimes = append(receiptTimes, clock.Mono())
	}
	peer := q.WritePeers()[0]
	for range 2 {
		if q.SendWrite(peer, code, raw, transport.SendAttempt{}, done) != transport.Queued {
			t.Fatal("normal admission refused")
		}
	}
	if q.SendWrite(peer, code, raw, transport.SendAttempt{}, done) != transport.QueueFull {
		t.Fatal("capacity did not separate one active write and one waiting entry")
	}
	// Only the caller's buffer is replaced after admission; no changed bytes
	// are submitted or delivered on the simulated stream.
	copy(raw, normalMessage(t, 2))
	clock.AdvanceTo(4 * time.Millisecond)
	if len(receipts) != 0 || len(arrivalTimes) != 0 {
		t.Fatal("queue admission became write success or arrival")
	}
	clock.AdvanceTo(10 * time.Millisecond)
	if len(receipts) != 2 || receiptTimes[0] != 5*time.Millisecond || receiptTimes[1] != 10*time.Millisecond || len(arrivalTimes) != 0 {
		t.Fatal("FIFO write completion or independent link delay", receiptTimes, arrivalTimes)
	}
	clock.AdvanceTo(30 * time.Millisecond)
	if len(arrivalTimes) != 2 || arrivalTimes[0] != 25*time.Millisecond || arrivalTimes[1] != 30*time.Millisecond {
		t.Fatal("remote arrival did not follow write and link service", arrivalTimes)
	}
	for _, r := range receipts {
		if r.Target != peer || r.Result != transport.LocalWriteOK || r.Code != code || r.PayloadSHA256 != sha256.Sum256(original) {
			t.Fatal("receipt lost original request ownership", r)
		}
	}
}

func TestQueueNormalCloseAndReconnect(t *testing.T) {
	for _, at := range []time.Duration{0, 5 * time.Millisecond, 7 * time.Millisecond, 10 * time.Millisecond} {
		t.Run(at.String(), func(t *testing.T) {
			var clock manualclock.Clock
			arrivals := 0
			var got []transport.WriteReceipt
			q := newQueue(t, &clock, Options{Waiting: 2, WriteTime: 5 * time.Millisecond, LinkTime: time.Second}, func(uint64, []byte) { arrivals++ })
			peer := q.WritePeers()[0]
			for round := uint64(1); round <= 3; round++ {
				if q.SendWrite(peer, uint64(codec.CodeRoundChange), normalMessage(t, round), transport.SendAttempt{}, func(r transport.WriteReceipt) { got = append(got, r) }) != transport.Queued {
					t.Fatal("admission")
				}
			}
			clock.AdvanceTo(at)
			q.Close()
			q.Close()
			replacement := newQueue(t, &clock, Options{Waiting: 1}, func(uint64, []byte) { arrivals++ })
			if replacement.WritePeers()[0].Session == peer.Session || len(q.WritePeers()) != 0 {
				t.Fatal("reconnect revived or reused old stream")
			}
			if replacement.SendWrite(peer, uint64(codec.CodeRoundChange), normalMessage(t, 4), transport.SendAttempt{}, func(transport.WriteReceipt) { t.Fatal("rejected old target got callback") }) != transport.NotAttached {
				t.Fatal("replacement accepted old stream target")
			}
			clock.AdvanceTo(2 * time.Second)
			if len(got) != 3 || arrivals != 0 {
				t.Fatal("close lost/duplicated receipt or delivered old stream", got, arrivals)
			}
			for i, r := range got {
				want := transport.LocalWriteCancelled
				if i < int(at/(5*time.Millisecond)) {
					want = transport.LocalWriteOK
				}
				if r.Target != peer || r.Result != want || r.PayloadSHA256 != sha256.Sum256(normalMessage(t, uint64(i+1))) {
					t.Fatal("terminal receipt not original FIFO request", i, r)
				}
			}
		})
	}
}

func TestQueueLedgerSuccessBeforeArrival(t *testing.T) {
	var clock manualclock.Clock
	arrivals := 0
	q := newQueue(t, &clock, Options{Waiting: 1, WriteTime: time.Millisecond, LinkTime: time.Second}, func(uint64, []byte) { arrivals++ })
	ledger, err := transport.NewWriteLedger(transport.WriteLedgerOptions{Pending: 4, PerPeer: 2, KeyWithCode: true})
	if err != nil {
		t.Fatal(err)
	}
	peer, code, raw := q.WritePeers()[0], uint64(codec.CodeRoundChange), normalMessage(t, 1)
	ticket, decision := ledger.Prepare(peer, code, raw)
	if decision != transport.WriteReserved {
		t.Fatal(decision)
	}
	result := q.SendWrite(peer, code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) {
		if !ledger.Complete(ticket, r) {
			t.Fatal("simulated local success not retained")
		}
	})
	ledger.QueueResult(ticket, result)
	if ledger.Recent(peer.Addr, code, raw) {
		t.Fatal("queue admission incorrectly registered recent")
	}
	clock.AdvanceTo(time.Millisecond)
	if !ledger.Recent(peer.Addr, code, raw) || arrivals != 0 {
		t.Fatal("write completion and remote arrival conflated")
	}
	q.Close()
	clock.AdvanceTo(2 * time.Second)
	if !ledger.Recent(peer.Addr, code, raw) || arrivals != 0 {
		t.Fatal("normal close changed completed cache history or delivered closed stream")
	}
}

func TestQueueZeroDelayReentrantEnqueueAndHorizon(t *testing.T) {
	var clock manualclock.Clock
	var order []string
	q := newQueue(t, &clock, Options{Waiting: 1}, func(uint64, []byte) { order = append(order, "arrival") })
	peer, raw, code := q.WritePeers()[0], normalMessage(t, 1), uint64(codec.CodeRoundChange)
	if q.SendWrite(peer, code, raw, transport.SendAttempt{}, func(transport.WriteReceipt) {
		order = append(order, "first")
		if q.SendWrite(peer, code, raw, transport.SendAttempt{}, func(transport.WriteReceipt) { order = append(order, "second") }) != transport.Queued {
			t.Fatal("reentrant enqueue refused")
		}
	}) != transport.Queued || len(order) != 0 {
		t.Fatal("zero service ran before clock driver")
	}
	clock.AdvanceTo(0)
	if len(order) != 4 || order[0] != "first" || order[1] != "arrival" || order[2] != "second" || order[3] != "arrival" {
		t.Fatal("zero-service callback order", order)
	}
	clock.AdvanceTo(time.Duration(math.MaxInt64) - 1)
	q = newQueue(t, &clock, Options{Waiting: 1, WriteTime: 2}, func(uint64, []byte) { t.Fatal("overflow arrival") })
	peer = q.WritePeers()[0]
	called := 0
	q.SendWrite(peer, code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) {
		called++
		if r.Result != transport.LocalWriteCancelled {
			t.Fatal("unrepresentable future reported completion")
		}
	})
	clock.AdvanceTo(time.Duration(math.MaxInt64))
	if called != 0 {
		t.Fatal("horizon completed early")
	}
	q.Close()
	if called != 1 {
		t.Fatal("horizon request not cancelled")
	}
}

func TestQueueCompletionCanCloseReentrantly(t *testing.T) {
	var clock manualclock.Clock
	q := newQueue(t, &clock, Options{Waiting: 1}, func(uint64, []byte) { t.Fatal("closed stream arrival") })
	peer, code, raw := q.WritePeers()[0], uint64(codec.CodeRoundChange), normalMessage(t, 1)
	var got []transport.LocalWriteResult
	for range 2 {
		if q.SendWrite(peer, code, raw, transport.SendAttempt{}, func(r transport.WriteReceipt) { got = append(got, r.Result); q.Close() }) != transport.Queued {
			t.Fatal("admission")
		}
	}
	clock.AdvanceTo(0)
	if len(got) != 2 || got[0] != transport.LocalWriteOK || got[1] != transport.LocalWriteCancelled {
		t.Fatal("reentrant close terminal order", got)
	}
}

func TestQueueConfigurationAndAbsentCallback(t *testing.T) {
	var clock manualclock.Clock
	for _, opt := range []Options{{}, {Waiting: -1}, {Waiting: 1, WriteTime: -1}, {Waiting: 1, LinkTime: -1}, {Waiting: 1, WriteTime: time.Duration(math.MaxInt64), LinkTime: 1}} {
		if _, err := New(&clock, types.Address{7}, opt, func(uint64, []byte) {}); err == nil {
			t.Fatal("accepted invalid model configuration", opt)
		}
	}
	if _, err := New(nil, types.Address{7}, Options{Waiting: 1}, func(uint64, []byte) {}); err == nil {
		t.Fatal("missing clock")
	}
	if _, err := New(&clock, types.Address{7}, Options{Waiting: 1}, nil); err == nil {
		t.Fatal("missing arrival sink")
	}
	q := newQueue(t, &clock, Options{Waiting: 1}, func(uint64, []byte) { t.Fatal("rejected request arrived") })
	if q.SendWrite(q.WritePeers()[0], uint64(codec.CodeRoundChange), normalMessage(t, 1), transport.SendAttempt{}, nil) != transport.NotAttached {
		t.Fatal("accepted request without terminal sink")
	}
	clock.AdvanceTo(time.Second)
}
