package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/event/schema"
	"github.com/0xmhha/wbft/types"
)

func TestOwnSendEventCarriesSignedMessageView(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	a := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, a)
	checked := 0
	for _, rec := range n.events.kinds(event.Send) {
		if rec.Fields["cause"] != event.CauseBroadcast {
			continue
		}
		key, ok := rec.Fields["dedup_key"].(string)
		if !ok {
			t.Fatal("own SEND has no payload identity")
		}
		for _, wire := range n.net.sent {
			if codec.DedupKey(wire.payload).Hex() != key {
				continue
			}
			m, err := codec.DecodeMessage(codec.Code(wire.code), wire.payload)
			if err != nil {
				t.Fatal(err)
			}
			want := event.ViewOf(m.View)
			if rec.View == nil || *rec.View != *want {
				t.Fatalf("SEND view=%+v, signed message view=%+v, code=%d", rec.View, want, wire.code)
			}
			checked++
			break
		}
	}
	if checked < 2 {
		t.Fatal("PREPARE and COMMIT were not both checked", checked)
	}
}

// Check against the signed transport bytes, independently of the observation.
func assertSignedSend(t *testing.T, rec event.Record, wire sent, self types.Address, cause event.SendCause) {
	t.Helper()
	m, err := codec.DecodeMessage(codec.Code(wire.code), wire.payload)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.RecoverDataSigner(signing, m.Signature)
	if err != nil || signer != self {
		t.Fatal("wire signature does not bind self", signer, err)
	}
	want := event.ViewOf(m.View)
	sum := sha256.Sum256(wire.payload)
	if rec.Kind != event.Send || rec.View == nil || *rec.View != *want ||
		rec.Fields["code"] != wire.code || rec.Fields["cause"] != cause ||
		rec.Fields["dedup_key"] != codec.DedupKey(wire.payload).Hex() ||
		rec.Fields["payload_sha256"] != "0x"+hex.EncodeToString(sum[:]) {
		t.Fatalf("SEND does not describe signed wire message: %+v view=%+v want=%+v", rec, rec.View, want)
	}
	var raw bytes.Buffer
	if err := event.NewWriter(&raw, self, "synthetic-send").Write(rec, event.Stamp{Wall: time.Unix(1700000000, 0)}); err != nil {
		t.Fatal(err)
	}
	check, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Validate(bytes.TrimSpace(raw.Bytes())); err != nil {
		t.Fatal(err, raw.String())
	}
}

func TestBroadcastSendEvidenceUsesMessageRatherThanCurrentView(t *testing.T) {
	k := newKeys(t, 4)
	for _, code := range []codec.Code{codec.CodePreprepare, codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange} {
		for _, wide := range []bool{false, true} {
			t.Run(fmt.Sprintf("code-%d/wide-%t", code, wide), func(t *testing.T) {
				for _, observed := range []bool{true, false} {
					n := newTNode(t, k, 1)
					n.boot()
					seq, round := big.NewInt(11), big.NewInt(3)
					if wide {
						seq.Add(seq, new(big.Int).Lsh(big.NewInt(1), 70))
						round.Add(round, new(big.Int).Lsh(big.NewInt(1), 66))
					}
					h, err := types.HeightFromBig(seq)
					if err != nil {
						t.Fatal(err)
					}
					rd, err := types.RoundFromBig(round)
					if err != nil {
						t.Fatal(err)
					}
					v := types.View{Sequence: h, Round: rd}
					if n.r.core.Snapshot().View.Cmp(v) == 0 {
						t.Fatal("counterexample must differ from core view")
					}
					b := block(t, 11, 1, k.addrs[1], codec.BlockHash(n.chain.head))
					b.Header.Number = h
					m := &codec.Message{Code: code, View: v, Digest: codec.BlockHash(b.Header)}
					if code == codec.CodePreprepare {
						m.Proposal = b
					}
					cause := event.CauseBroadcast
					sc := &stepCtx{step: 41, q: queued{in: consensus.Start{}}}
					if code == codec.CodeRoundChange {
						sc.q.in = consensus.Timeout{Kind: consensus.RetryTimer}
						cause = event.CauseRetry
					}
					if !observed {
						n.r.d.Events = nil
					}
					n.r.broadcast(sc, consensus.Broadcast{Msg: m, Validators: k.vs, SealData: privvalRequest(m, b).SealData})
					if n.r.Halted() != nil || len(n.net.sent) != 1 {
						t.Fatal("send changed", n.r.Halted(), len(n.net.sent))
					}
					wire := n.net.sent[0]
					// FileSigner persists and reuses the actual signature, independently of events.
					again, err := n.signer.SignVote(privvalRequest(m, b))
					if err != nil {
						t.Fatal(err)
					}
					signed := *m
					signed.Signature, signed.Seal = again.Signature, again.Seal
					wantWire, err := codec.EncodeMessage(&signed)
					if err != nil || !bytes.Equal(wire.payload, wantWire) {
						t.Fatal("observation changed wire bytes", err)
					}
					if len(m.Signature) != 0 || len(m.Seal) != 0 {
						t.Fatal("caller message mutated")
					}
					if !bytes.Equal(n.r.lastOwn[ownKey{code: uint64(code)}], wire.payload) {
						t.Fatal("last own bytes differ")
					}
					last := n.r.internal[len(n.r.internal)-1]
					delivered, ok := last.in.(consensus.Message)
					if !ok || last.via != viaInternal || delivered.Peer != k.addrs[1] || !bytes.Equal(delivered.Payload, wire.payload) {
						t.Fatal("self delivery changed")
					}
					records, _, err := wal.ReadAll(n.fs, "/wal")
					if err != nil {
						t.Fatal(err)
					}
					lastRecord := records[len(records)-1]
					var own ownRec
					if lastRecord.Kind != walOwnMsg || rlp.DecodeStrict(lastRecord.Body, &own) != nil || own.Code != wire.code || !bytes.Equal(own.Payload, wire.payload) {
						t.Fatal("durable WAL does not contain exact signed bytes")
					}
					sends := n.events.kinds(event.Send)
					if !observed {
						if len(sends) != 0 {
							t.Fatal("disabled observation wrote SEND")
						}
						continue
					}
					if len(sends) != 1 {
						t.Fatal("wrong SEND count", len(sends))
					}
					assertSignedSend(t, sends[0], wire, k.addrs[1], cause)
					if sends[0].Fields["engine_run"] != n.r.engineRun {
						t.Fatal("engine ownership changed")
					}
					stamp := n.events.stamps[len(n.events.stamps)-1]
					if stamp.Step == nil || *stamp.Step != sc.step {
						t.Fatal("step ownership lost")
					}
				}
			})
		}
	}
}

func privvalRequest(m *codec.Message, b *types.Block) privval.VoteRequest {
	seal := types.PrepareSeal
	if m.Code == codec.CodeCommit {
		seal = types.CommitSeal
	}
	return privval.VoteRequest{Msg: m, SealData: codec.SealData(b.Header, 3, seal)}
}

func TestReplaySendEvidenceDescribesExactResentBytes(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, b)
	original := append([]byte(nil), n.net.own(codec.CodeCommit)[0]...)
	n.crash()
	n.net.sent = nil
	n.boot()
	if !n.r.LastReplay().Replayed || n.r.LastReplay().Stopped != "" {
		t.Fatal("replay failed", n.r.LastReplay())
	}
	checked := 0
	for _, rec := range n.events.kinds(event.Send) {
		if rec.Fields["cause"] != event.CauseReplay {
			continue
		}
		matched := false
		for _, wire := range n.net.sent {
			if wire.code != rec.Fields["code"] {
				continue
			}
			assertSignedSend(t, rec, wire, k.addrs[1], event.CauseReplay)
			if wire.code == uint64(codec.CodeCommit) && !bytes.Equal(wire.payload, original) {
				t.Fatal("replay changed COMMIT bytes")
			}
			matched = true
			checked++
			break
		}
		if !matched {
			t.Fatal("replay SEND without transmitted bytes")
		}
	}
	if checked < 2 {
		t.Fatal("PREPARE and COMMIT replay not both observed", checked)
	}
	for i, rec := range n.events.recs {
		if rec.Kind == event.Send && rec.Fields["cause"] == event.CauseReplay && n.events.stamps[i].Step != nil {
			t.Fatal("replay invented a current core step")
		}
	}
}

func TestUnpositionedRelayDoesNotBorrowCurrentView(t *testing.T) {
	k := newKeys(t, 4)
	b := block(t, 11, 1, k.addrs[0], types.Hash{})
	valid := k.vote(t, 0, codec.CodeCommit, view(11, 3), b)
	for _, payload := range [][]byte{{0xff}, valid} {
		n := newTNode(t, k, 1)
		n.boot()
		sc := &stepCtx{step: 12, outs: []consensus.Output{consensus.Relay{Validators: k.vs, Code: codec.CodeCommit, Payload: payload}}}
		n.r.execute(sc)
		recs := n.events.kinds(event.Send)
		if len(recs) != 1 || recs[0].View != nil {
			t.Fatal("relay borrowed a view", recs)
		}
		if recs[0].Fields["dedup_key"] != codec.DedupKey(payload).Hex() || recs[0].Fields["cause"] != event.CauseRelay {
			t.Fatal("relay identity changed")
		}
		if len(n.net.sent) != 1 || !bytes.Equal(n.net.sent[0].payload, payload) {
			t.Fatal("relay bytes changed")
		}
	}
}

func TestFailedBroadcastDoesNotInventSendEvidence(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		n := newTNode(t, newKeys(t, 4), 1)
		n.boot()
		m := &codec.Message{Code: codec.CodeRoundChange, View: view(11, 3)}
		sc := &stepCtx{step: 20, q: queued{in: consensus.Start{}}}
		if unsigned {
			n.r.d.Signer = nil
		} else {
			n.r.broadcast(sc, consensus.Broadcast{Msg: m, Validators: n.k.vs})
			// A lower-height request is refused by the persisted signer.
			m = &codec.Message{Code: codec.CodeRoundChange, View: view(10, 2)}
		}
		beforeEvents, beforeWire := len(n.events.kinds(event.Send)), len(n.net.sent)
		n.r.broadcast(sc, consensus.Broadcast{Msg: m, Validators: n.k.vs})
		if len(n.events.kinds(event.Send)) != beforeEvents || len(n.net.sent) != beforeWire {
			t.Fatal("unsent message gained SEND evidence")
		}
		last := n.r.internal[len(n.r.internal)-1]
		if _, ok := last.in.(consensus.BroadcastFailed); !ok {
			t.Fatal("failure delivery changed")
		}
	}
}

func TestTimerDrivenRetrySendRetainsSignedView(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.boot()
	n.advance(2 * time.Second)
	n.advance(2 * time.Second)
	causes := map[event.SendCause]bool{}
	for _, rec := range n.events.kinds(event.Send) {
		if rec.Fields["code"] != uint64(codec.CodeRoundChange) {
			continue
		}
		cause, ok := rec.Fields["cause"].(event.SendCause)
		if !ok {
			t.Fatal("untyped send cause")
		}
		matched := false
		for _, wire := range n.net.sent {
			if wire.code == uint64(codec.CodeRoundChange) && rec.Fields["dedup_key"] == codec.DedupKey(wire.payload).Hex() {
				assertSignedSend(t, rec, wire, k.addrs[1], cause)
				causes[cause], matched = true, true
				break
			}
		}
		if !matched {
			t.Fatal("timer SEND without exact wire message")
		}
	}
	if !causes[event.CauseBroadcast] || !causes[event.CauseRetry] {
		t.Fatal("normal and retry ROUND-CHANGE not both checked", causes)
	}
}
