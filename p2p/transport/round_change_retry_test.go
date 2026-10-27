package transport

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func normalOwnRetry(t *testing.T, payload []byte) (RoundChangeRetryRequest, DedupOptions) {
	t.Helper()
	m, err := codec.DecodeMessage(codec.CodeRoundChange, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	self, err := ecdsa.RecoverDataSigner(body, m.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return RoundChangeRetryRequest{View: m.View, Generation: 2, SigningKey: codec.DedupKey(body), PreviousPayload: payload,
		Source: RoundChangeRetrySource{EngineRun: 1, Step: 2, Output: 3}}, DedupOptions{Self: self, RoundChangeRetry: true}
}

func TestNormalOwnRoundChangeRetryLegacyPair(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			raw := ledgerNormalMessage(t, 1)
			request, options := normalOwnRetry(t, raw)
			options.RoundChangeRetry = enabled
			p1, p2, outsider := addr(1), addr(2), addr(9)
			tr := &cacheProbeTransport{fakeTransport: fakeTransport{peers: []types.Address{p2, options.Self, p1, p2, outsider}}}
			d, err := NewDedup(tr, options)
			if err != nil {
				t.Fatal(err)
			}
			vs := set(t, options.Self, p1, p2)
			if len(d.Broadcast(vs, uint64(codec.CodeRoundChange), raw, event.CauseBroadcast)) != 2 {
				t.Fatal("initial broadcast")
			}
			for _, cause := range []event.SendCause{event.CauseRetry, event.CauseRelay} {
				if p := d.GossipTargets(vs, uint64(codec.CodeRoundChange), raw, cause); len(p.Targets) != 0 || len(p.Suppressed) != 2 {
					t.Fatal("event label changed ordinary recent exclusion", p)
				}
			}
			plan := d.RetryOwnRoundChange(vs, raw, request)
			if enabled {
				if len(plan.Targets) != 2 || len(plan.Suppressed) != 0 || len(tr.sends) != 2 {
					t.Fatal("eligible same-payload retry", plan)
				}
				op := tr.ops[len(tr.ops)-1]
				if op.Retry.Version != 1 || op.Retry.Generation != request.Generation || op.Retry.SigningKey != request.SigningKey {
					t.Fatal("retry source missing", op)
				}
			} else if len(plan.Targets) != 0 || len(tr.sends) != 1 {
				t.Fatal("disabled dedicated route changed legacy sends")
			}
			if !d.Known(raw) || !d.SentOrReceived(p1, raw) || !d.SentOrReceived(p2, raw) {
				t.Fatal("retry cleared ordinary cache entries")
			}
		})
	}
}

type normalRetryWrite struct {
	receipt WriteReceipt
	done    func(WriteReceipt)
}
type normalRetryWriteTransport struct {
	fakeTransport
	peers  []WritePeer
	writes []normalRetryWrite
}

func (w *normalRetryWriteTransport) WritePeers() []WritePeer { return w.peers }
func (w *normalRetryWriteTransport) SendWrite(target WritePeer, code uint64, payload []byte, _ SendAttempt, done func(WriteReceipt)) SendResult {
	w.writes = append(w.writes, normalRetryWrite{WriteReceipt{Target: target, Code: code, PayloadSHA256: sha256.Sum256(payload), Result: LocalWriteOK}, done})
	return Queued
}
func (w *normalRetryWriteTransport) complete(from int) {
	for _, write := range w.writes[from:] {
		write.done(write.receipt)
	}
}

// This is a normal queue/completion fixture. Actual SDK WriteMsg proof remains
// separate; a queued request is never counted as a completed local write here.
func TestNormalOwnRoundChangeRetryCompletedOwnership(t *testing.T) {
	raw := ledgerNormalMessage(t, 1)
	request, options := normalOwnRetry(t, raw)
	p1, p2 := addr(1), addr(2)
	trace := &writeTransitions{}
	options.KeyWithCode, options.RecordAfterSend = true, true
	options.CompletedWrites = &WriteLedgerOptions{Pending: 2, PerPeer: 1, KeyWithCode: true, Trace: trace}
	tr := &normalRetryWriteTransport{peers: []WritePeer{{Addr: p1, Session: NewWriteSession()}, {Addr: p2, Session: NewWriteSession()}}}
	d, err := NewDedup(tr, options)
	if err != nil {
		t.Fatal(err)
	}
	vs := set(t, options.Self, p1, p2)
	d.Broadcast(vs, uint64(codec.CodeRoundChange), raw, event.CauseBroadcast)
	if len(tr.writes) != 2 || d.SentOrReceivedCode(p1, uint64(codec.CodeRoundChange), raw) {
		t.Fatal("queue became a recent receipt")
	}
	if p := d.RetryOwnRoundChange(vs, raw, request); len(p.Pending) != 2 || len(tr.writes) != 2 {
		t.Fatal("retry bypassed pending ownership", p)
	}
	tr.complete(0)
	if p := d.GossipTargets(vs, uint64(codec.CodeRoundChange), raw, event.CauseRetry); len(p.Suppressed) != 2 || len(p.Targets) != 0 {
		t.Fatal("cause bypassed completed recent", p)
	}
	other := ledgerNormalMessage(t, 2)
	d.Broadcast(vs, uint64(codec.CodeRoundChange), other, event.CauseBroadcast)
	if p := d.RetryOwnRoundChange(vs, raw, request); len(p.Limited) != 2 || len(tr.writes) != 4 {
		t.Fatal("retry bypassed original pending limits", p)
	}
	tr.complete(2)
	if p := d.RetryOwnRoundChange(vs, raw, request); len(p.Targets) != 2 || len(tr.writes) != 6 {
		t.Fatal("completed recent retry did not reserve", p)
	}
	if p := d.RetryOwnRoundChange(vs, raw, request); len(p.Pending) != 2 || len(tr.writes) != 6 {
		t.Fatal("retry duplicated outstanding tickets", p)
	}
	tr.complete(4)
	if !d.SentOrReceivedCode(p1, uint64(codec.CodeRoundChange), raw) || d.completedWrites.Pending() != 0 {
		t.Fatal("normal completion lost registration or ownership")
	}
	d.CloseCompletedWrites()
	if p := d.RetryOwnRoundChange(vs, raw, request); len(p.Unavailable) != 2 || len(tr.writes) != 6 {
		t.Fatal("retry reopened a closed ledger", p)
	}
}
