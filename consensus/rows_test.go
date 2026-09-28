package consensus

import (
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// signWith signs m with a key that is not one of the validators.
func signWith(t *testing.T, key []byte, m *codec.Message) *codec.Message {
	t.Helper()
	k, err := ecdsa.PrivateKeyFromBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	c := *m
	p, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Signature, err = ecdsa.SignData(p, k); err != nil {
		t.Fatal(err)
	}
	return &c
}

// Every row of the message-handling outcome table (A-05 section 16), with
// its relay decision.
func TestOutcomeRows(t *testing.T) {
	for k := range rowsSeen { //wbft:unordered the map is emptied
		delete(rowsSeen, k)
	}

	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)

	// 1: unknown code, undecodable payload.
	h.step(Message{Code: 0x11, Payload: h.encode(h.prepare(0, view(10, 0), b)), Peer: h.addrs[0]})
	h.expect(ClassNone, rowUndecodable, false)
	h.step(Message{Code: codec.CodePrepare, Payload: []byte{0x01}, Peer: h.addrs[0]})
	h.expect(ClassNone, rowUndecodable, false)
	// 2: signer outside the set.
	h.deliver(0, signWith(t, vectorKey(7), &codec.Message{Code: codec.CodePrepare, View: view(10, 0), Digest: blockHash(b), Seal: make([]byte, 96)}))
	h.expect(ClassNone, rowBadSignature, false)
	// 3, 4: too far ahead, old.
	h.deliver(2, h.prepare(2, view(12, 0), h.block(12, 1, h.addrs[0])))
	h.expect(TooFar, rowTooFar, false)
	h.deliver(2, h.prepare(2, view(8, 0), h.block(8, 1, h.addrs[0])))
	h.expect(Old, rowOld, false)
	// 6, 7: backlogged; the same slot again and a message of the node
	// itself are dropped.
	h.deliver(2, h.prepare(2, view(10, 0), b))
	h.expect(Future, rowBacklogged, false)
	h.deliver(2, h.prepare(2, view(10, 0), b))
	h.expect(Future, rowBacklogDropped, false)
	h.deliver(1, h.commit(1, view(11, 0), h.block(11, 1, h.addrs[0])))
	h.expect(Future, rowBacklogDropped, false)
	// 8: extra seal without a target.
	h.deliver(2, h.prepare(2, view(9, 0), h.env.head))
	h.expect(ExtraSeal, rowExtraNoTarget, true)
	// 13: PRE-PREPARE not from the proposer; 14: from the future.
	h.deliver(2, h.preprepare(2, view(10, 0), b, nil, nil))
	h.expect(Process, rowPreprepareReject, false)
	fut := h.proposal(7)
	h.env.future[blockHash(fut)] = time.Second
	h.deliver(0, h.preprepare(0, view(10, 0), fut, nil, nil))
	h.expect(Process, rowPreprepareFuture, false)
	bad := h.proposal(8)
	h.env.invalid[blockHash(bad)] = true
	h.deliver(0, h.preprepare(0, view(10, 0), bad, nil, nil))
	h.expect(Process, rowPreprepareReject, false)
	// 15: accepted; the backlogged PREPARE of validator 2 is replayed.
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.expect(Process, rowPreprepareAccept, true)
	if len(outputsOf[Schedule](h.out)) != 1 {
		t.Fatalf("replay not scheduled: %v", h.out)
	}
	own := h.broadcasts()[0]
	// 5: a second PRE-PREPARE of the view.
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.expect(Invalid, rowInvalid, false)
	// 16: PREPARE for another digest.
	h.deliver(2, h.prepare(2, view(10, 0), h.proposal(9)))
	h.expect(Process, rowPrepareInvalid, false)
	// 17, 18: stored, then the quorum.
	h.selfDeliver(own)
	h.expect(Process, rowPrepareStored, true)
	h.deliver(0, h.prepare(0, view(10, 0), b))
	h.expect(Process, rowPrepareStored, true)
	h.deliver(2, h.prepare(2, view(10, 0), b))
	h.expect(Process, rowPrepareQuorum, true)
	ownCommit := h.broadcasts()[0]
	// 10, 11, 9: extra seals after the quorum.
	late := h.prepare(3, view(10, 0), b)
	h.deliver(3, late)
	h.expect(ExtraSeal, rowExtraStored, true)
	h.deliver(3, late)
	h.expect(ExtraSeal, rowExtraNotNewer, true)
	h.deliver(3, h.prepare(3, view(10, 0), h.proposal(9)))
	h.expect(ExtraSeal, rowExtraInvalid, false)
	// 19, 20, 21: COMMITs.
	h.deliver(2, h.commit(2, view(10, 0), h.proposal(9)))
	h.expect(Process, rowCommitInvalid, false)
	h.selfDeliver(ownCommit)
	h.expect(Process, rowCommitStored, true)
	h.deliver(0, h.commit(0, view(10, 0), b))
	h.expect(Process, rowCommitStored, true)
	h.deliver(2, h.commit(2, view(10, 0), b))
	h.expect(Process, rowCommitDecided, true)
	// 12: a PRE-PREPARE of the previous sequence at the prior round is an
	// extra seal of another code.
	h.env.head = b
	h.step(NewHead{})
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.expect(ExtraSeal, rowExtraOtherCode, false)

	// 22: finalize fails.
	f := newHarness(t, 4, 1)
	f.env.finalizeFail = true
	f.start()
	f.reachPrepared(b)
	f.selfDeliver(f.broadcasts()[0])
	f.deliver(0, f.commit(0, view(10, 0), b))
	f.deliver(2, f.commit(2, view(10, 0), b))
	f.expect(Process, rowCommitFinalFail, true)

	// ROUND-CHANGE rows. Node 1 is the proposer of round 1.
	r := newHarness(t, 4, 1)
	r.start()
	r.roundTimeout() // (10, 1)
	rcOwn := r.broadcasts()[0]
	// 23: prepared block of another sequence.
	b11 := r.block(11, 1, r.addrs[0])
	ps11 := []*codec.Message{r.prepare(0, view(10, 0), b11), r.prepare(2, view(10, 0), b11), r.prepare(3, view(10, 0), b11)}
	r.deliver(0, r.roundChange(0, view(10, 1), roundPtr(0), b11, ps11))
	r.expect(Process, rowRCOtherSequence, false)
	// 24: stored; 27: the quorum rule fails its own check (a prepared pair
	// without its PREPAREs is stored without it but is not "nil").
	r.selfDeliver(rcOwn)
	r.expect(Process, rowRCStored, true)
	r.step(Request{Block: r.proposal(5)})
	r.deliver(0, r.roundChange(0, view(10, 1), roundPtr(0), b, nil))
	r.expect(Process, rowRCStored, true)
	r.deliver(2, r.roundChange(2, view(10, 1), nil, nil, nil))
	r.expect(Process, rowRCNotJustified, true)
	if len(r.broadcasts()) != 0 {
		t.Fatal("PRE-PREPARE sent without justification")
	}
	// 26: a fourth ROUND-CHANGE without a pair justifies the request.
	r.deliver(3, r.roundChange(3, view(10, 1), nil, nil, nil))
	r.expect(Process, rowRCProposed, true)
	if bs := r.broadcasts(); len(bs) != 1 || bs[0].Msg.Code != codec.CodePreprepare || len(bs[0].Msg.RoundChanges) != 4 {
		t.Fatalf("PRE-PREPARE %+v", bs)
	}
	// 25: F+1 senders above the current round.
	r.deliver(0, r.roundChange(0, view(10, 3), nil, nil, nil))
	r.expect(Process, rowRCStored, true)
	r.deliver(2, r.roundChange(2, view(10, 3), nil, nil, nil))
	r.expect(Process, rowRCFPlusOne, true)
	r.wantView(10, 3, AcceptRequest)
	// 28: no block to propose (node 3 is the proposer of round 3 here).
	q := newHarness(t, 4, 1)
	q.start()
	q.roundTimeout()
	q.selfDeliver(q.broadcasts()[0])
	q.deliver(0, q.roundChange(0, view(10, 1), nil, nil, nil))
	q.deliver(2, q.roundChange(2, view(10, 1), nil, nil, nil))
	q.expect(Process, rowRCNoProposal, false)

	for row := 1; row <= 28; row++ {
		if !rowsSeen[row] {
			t.Errorf("row %d not checked", row)
		}
	}
}

// PREPAREs and COMMITs whose seal does not verify are rejected like a wrong
// digest; a sealer outside the set fails before the BLS check.
//
// Covers: WBFT-CRYPTO-043
func TestVerifySealMembership(t *testing.T) {
	h := newHarness(t, 5, 1)
	b := h.proposal(1)
	sd := codec.SealData(b.Header, 0, types.PrepareSeal)
	seal := h.blsK[4].Sign(sd).Bytes()
	full := h.vs
	four := newSetOf(t, h, 4)
	if !verifySeal(full, b.Header, 0, types.PrepareSeal, seal, h.addrs[4]) {
		t.Fatal("valid seal rejected")
	}
	if verifySeal(four, b.Header, 0, types.PrepareSeal, seal, h.addrs[4]) {
		t.Fatal("seal of a non-member accepted")
	}
	if verifySeal(full, b.Header, 1, types.PrepareSeal, seal, h.addrs[4]) {
		t.Fatal("seal for another round accepted")
	}
	if verifySeal(full, b.Header, 0, types.CommitSeal, seal, h.addrs[4]) {
		t.Fatal("seal of another type accepted")
	}
	if verifySeal(full, b.Header, 0, types.PrepareSeal, seal[:95], h.addrs[4]) {
		t.Fatal("short seal accepted")
	}
}
