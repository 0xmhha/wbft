package consensus

import (
	"errors"
	"github.com/0xmhha/wbft/observe/event"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// The tests of this file pin the reference behaviour of every place where an
// optional behaviour of a later milestone may differ. Each test names the
// behaviour it pins.

// The round timer keeps running after the decision; its expiry sends
// ROUND-CHANGE for the decided height with the lock.
func TestRefRoundTimerRunsAfterDecision(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachPrepared(b)
	h.selfDeliver(h.broadcasts()[0])
	h.deliver(0, h.commit(0, view(10, 0), b))
	h.deliver(2, h.commit(2, view(10, 0), b))
	if len(outputsOf[CancelTimers](h.out)) != 0 {
		t.Fatal("the decision cancelled timers")
	}
	if len(outputsOf[Commit](h.out)) != 1 {
		t.Fatal("no commit")
	}
	h.roundTimeout()
	h.wantView(10, 1, AcceptRequest)
	bs := h.broadcasts()
	if len(bs) != 1 {
		t.Fatalf("broadcasts %v", bs)
	}
	rc := bs[0].Msg
	if rc.Code != codec.CodeRoundChange || rc.View.Cmp(view(10, 1)) != 0 || rc.PreparedRound == nil ||
		!rc.PreparedRound.IsZero() || rc.PreparedDigest != blockHash(b) || len(rc.Prepares) != 3 {
		t.Fatalf("round change %+v", rc)
	}
	if v := h.vars(); v.LockedBlock == nil || *v.LockedBlock != blockHash(b) {
		t.Fatal("lock lost")
	}
}

// A round timeout processed after the head advanced but before its NewHead
// enters round 0 of the next sequence, keeps the certificate and sends
// ROUND-CHANGE (h+1, r+1) without a prepared pair; the retry then sends
// ROUND-CHANGE (h+1, 0).
func TestRefLateTimeoutCatchUp(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachPrepared(b)
	h.env.head = &types.Block{Header: b.Header, Body: b.Body}
	h.roundTimeout()
	h.wantView(11, 0, AcceptRequest)
	bs := h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.View.Cmp(view(11, 1)) != 0 || bs[0].Msg.PreparedRound != nil || len(bs[0].Msg.Prepares) != 3 {
		t.Fatalf("round change %+v", bs)
	}
	builds := outputsOf[RequestBuild](h.out)
	if len(builds) != 1 || builds[0].Round.Cmp(types.RoundFromUint64(1)) != 0 {
		t.Fatalf("build request %+v", builds)
	}
	var retry *ArmTimer
	for _, a := range outputsOf[ArmTimer](h.out) {
		if a.Kind == RetryTimer {
			retry = &a
		}
	}
	if retry == nil || !retry.Round.IsZero() {
		t.Fatalf("retry timer %+v", retry)
	}
	if h.vars().Certificate == nil {
		t.Fatal("certificate cleared")
	}
	h.step(Timeout{Kind: RetryTimer, Round: retry.Round, Gen: retry.Gen})
	bs = h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.View.Cmp(view(11, 0)) != 0 || len(bs[0].Msg.Prepares) != 3 {
		t.Fatalf("retry round change %+v", bs)
	}
	// NewHead for the same head changes nothing.
	h.step(NewHead{Header: b.Header})
	if len(h.out) != 0 {
		t.Fatalf("NewHead outputs %v", h.out)
	}
}

// The backlog replay of a source stops at its first message that is still
// FUTURE: in Preprepared a COMMIT holds back the PREPARE of the same source.
func TestRefBacklogStopsAtFirstFuture(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.deliver(2, h.prepare(2, view(10, 0), b))
	h.expect(Future, rowBacklogged, false)
	h.deliver(2, h.commit(2, view(10, 0), b))
	h.expect(Future, rowBacklogged, false)
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.expect(Process, rowPreprepareAccept, true)
	if s := outputsOf[Schedule](h.out); len(s) != 0 {
		t.Fatalf("replays scheduled in Preprepared: %v", s)
	}
	if len(h.vars().Backlog) != 2 {
		t.Fatalf("backlog %+v", h.vars().Backlog)
	}
}

// Messages of the next sequence are verified against the current set: a
// signer outside it is discarded.
func TestRefNextSequenceSignatureSet(t *testing.T) {
	h := newHarness(t, 5, 1)
	// The current set has validators 0 .. 3 only.
	h.env.vs = newSetOf(t, h, 4)
	h.start()
	b := h.block(11, 1, h.addrs[0])
	h.deliver(4, h.prepare(4, view(11, 0), b))
	h.expect(ClassNone, rowBadSignature, false)
	h.deliver(2, h.prepare(2, view(11, 0), b))
	h.expect(Future, rowBacklogged, false)
}

// prior is taken from the round the node leaves and its last accepted
// PRE-PREPARE, not from the head block.
func TestRefPriorFromLocalRound(t *testing.T) {
	h := newHarness(t, 4, 2)
	h.start()
	b := h.proposal(1)
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.roundTimeout() // round 1, PRE-PREPARE of round 0 carried
	h.wantView(10, 1, AcceptRequest)
	other := h.proposal(9) // the head is another block of height 10
	h.env.head = other
	h.step(NewHead{Header: other.Header})
	v := h.vars()
	if v.PriorRound.Cmp(types.RoundFromUint64(1)) != 0 || v.PriorProposal == nil || *v.PriorProposal != blockHash(b) {
		t.Fatalf("prior %s %v", v.PriorRound, v.PriorProposal)
	}
}

// A failed finalize sends ROUND-CHANGE (h, r+1) and stays in (h, r)
// Committed; the retry then repeats ROUND-CHANGE (h, r) with prepared round r.
func TestRefFinalizeFailure(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.env.finalizeFail = true
	h.start()
	b := h.proposal(1)
	h.reachPrepared(b)
	h.selfDeliver(h.broadcasts()[0])
	h.deliver(0, h.commit(0, view(10, 0), b))
	h.deliver(2, h.commit(2, view(10, 0), b))
	h.expect(Process, rowCommitFinalFail, true)
	h.wantView(10, 0, Committed)
	bs := h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.View.Cmp(view(10, 1)) != 0 {
		t.Fatalf("round change %+v", bs)
	}
	var retry ArmTimer
	for _, a := range outputsOf[ArmTimer](h.out) {
		retry = a
	}
	if retry.Kind != RetryTimer || !retry.Round.IsZero() {
		t.Fatalf("retry %+v", retry)
	}
	h.step(Timeout{Kind: RetryTimer, Round: retry.Round, Gen: retry.Gen})
	bs = h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.View.Cmp(view(10, 0)) != 0 || bs[0].Msg.PreparedRound == nil || !bs[0].Msg.PreparedRound.IsZero() {
		t.Fatalf("retry round change %+v", bs)
	}
}

// A retry expiry queued before the node entered a new height is processed:
// it sends ROUND-CHANGE (h+1, r_c) without a prepared pair.
func TestRefQueuedRetryAfterNewHeight(t *testing.T) {
	h := newHarness(t, 4, 2)
	h.start()
	h.roundTimeout() // (10, 1), retry armed with round 1
	h.env.head = h.proposal(1)
	h.step(NewHead{})
	h.wantView(11, 0, AcceptRequest)
	h.step(Timeout{Kind: RetryTimer, Round: types.RoundFromUint64(1)})
	bs := h.broadcasts()
	if len(bs) != 1 {
		t.Fatalf("broadcasts %v", h.out)
	}
	m := bs[0].Msg
	if m.View.Cmp(view(11, 1)) != 0 || m.PreparedRound != nil || m.PreparedBlock != nil || len(m.Prepares) != 0 {
		t.Fatalf("round change %+v", m)
	}
	h.wantView(11, 0, AcceptRequest)
}

// A retry expiry for a round below the current one sends nothing but re-arms
// the retry timer for the current round.
func TestRefRetryBelowCurrentRound(t *testing.T) {
	h := newHarness(t, 4, 2)
	h.start()
	h.roundTimeout()
	h.roundTimeout() // (10, 2)
	h.step(Timeout{Kind: RetryTimer, Round: types.RoundFromUint64(1)})
	if len(h.broadcasts()) != 0 {
		t.Fatal("sent a round change for a past round")
	}
	arms := outputsOf[ArmTimer](h.out)
	if len(arms) != 1 || arms[0].Kind != RetryTimer || arms[0].Round.Cmp(types.RoundFromUint64(2)) != 0 {
		t.Fatalf("arms %+v", arms)
	}
}

// The F+1 rule fires only when the count of senders above the node's round
// is in the window F < num <= F+1; a count above the window does not fire.
func TestRefFPlusOneWindow(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.deliver(0, h.roundChange(0, view(10, 2), nil, nil, nil))
	h.expect(Process, rowRCStored, true)
	h.deliver(2, h.roundChange(2, view(10, 3), nil, nil, nil))
	h.expect(Process, rowRCFPlusOne, true)
	h.wantView(10, 2, AcceptRequest)

	// Two more senders above round 2 arrive while the node cannot count
	// them one by one: the count jumps from 1 to 3 (F = 1, F+1 = 2).
	h2 := newHarness(t, 4, 1)
	h2.start()
	e := h2.s.rcs.entry(5)
	for _, i := range []int{0, 2} {
		m := h2.roundChange(i, view(10, 5), nil, nil, nil)
		v, err := RecoverDecoded(m, nil)
		if err != nil {
			t.Fatal(err)
		}
		e.msgs[v.Source] = v
	}
	h2.deliver(3, h2.roundChange(3, view(10, 4), nil, nil, nil))
	h2.expect(Process, rowRCStored, true)
	h2.wantView(10, 0, AcceptRequest)
}

// The prepared certificate is cleared only when start_new_round is called
// with round 0: a lock released by the bad-block rule keeps it, and a
// round change carries it without a prepared pair.
func TestRefCertificateLifetime(t *testing.T) {
	h := newHarness(t, 4, 2)
	h.start()
	b := h.proposal(1)
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.selfDeliver(h.broadcasts()[0])
	h.deliver(0, h.prepare(0, view(10, 0), b))
	h.deliver(1, h.prepare(1, view(10, 0), b))
	h.wantView(10, 0, Prepared)
	h.env.bad[blockHash(b)] = true
	h.roundTimeout()
	v := h.vars()
	if v.LockedBlock != nil || v.LockedRound != nil {
		t.Fatal("lock on a bad block kept")
	}
	if len(v.Certificate) != 3 {
		t.Fatalf("certificate %+v", v.Certificate)
	}
	bs := h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.PreparedRound != nil || len(bs[0].Msg.Prepares) != 3 {
		t.Fatalf("round change %+v", bs)
	}
	// A new head (round 0) clears it.
	h.env.head = b
	h.step(NewHead{})
	if h.vars().Certificate != nil {
		t.Fatal("certificate kept across a new height")
	}
}

// An extra seal without a target block stores nothing and is relayed.
func TestRefExtraSealWithoutTarget(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.deliver(2, h.prepare(2, view(9, 0), h.env.head))
	h.expect(ExtraSeal, rowExtraNoTarget, true)
	if len(h.vars().ExtraPrepareSeals) != 0 {
		t.Fatal("stored a seal without a target")
	}
}

// Replacing a source's ROUND-CHANGE never lowers the highest prepared round
// of that round.
func TestRefHighestPreparedMonotone(t *testing.T) {
	h := newHarness(t, 4, 3)
	h.start()
	h.roundTimeout() // (10, 1)
	b := h.proposal(1)
	ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(1, view(10, 0), b), h.prepare(2, view(10, 0), b)}
	h.deliver(0, h.roundChange(0, view(10, 1), roundPtr(0), b, ps))
	h.expect(Process, rowRCStored, true)
	h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
	h.expect(Process, rowRCStored, true)
	var got *RoundChangeVar
	for _, rc := range h.vars().RoundChanges {
		if rc.Round == 1 {
			got = &rc
		}
	}
	if got == nil || got.PreparedBlock == nil || *got.PreparedBlock != blockHash(b) || got.PreparedRound == nil || !got.PreparedRound.IsZero() {
		t.Fatalf("round 1 entry %+v", got)
	}
}

// The bad-block rule also clears the extra seals of the previous sequence.
func TestRefBadBlockClearsPreviousExtraSeals(t *testing.T) {
	h := newHarness(t, 4, 2)
	h.env.head = h.block(8, 0, h.addrs[3])
	h.start() // (9, 0); proposer of round 0 is validator 0
	b9 := h.block(9, 1, h.addrs[3])
	h.deliver(0, h.preprepare(0, view(9, 0), b9, nil, nil))
	h.expect(Process, rowPreprepareAccept, true)
	h.env.head = b9
	h.step(NewHead{}) // (10, 0), prior = (0, b9)
	h.deliver(1, h.prepare(1, view(9, 0), b9))
	h.expect(ExtraSeal, rowExtraStored, true)
	if len(h.vars().ExtraPrepareSeals) != 1 {
		t.Fatal("extra seal of height 9 not stored")
	}
	b := h.proposal(2)
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.selfDeliver(h.broadcasts()[0])
	h.deliver(0, h.prepare(0, view(10, 0), b))
	h.deliver(1, h.prepare(1, view(10, 0), b))
	h.wantView(10, 0, Prepared)
	h.env.bad[blockHash(b)] = true
	h.roundTimeout()
	if n := len(h.vars().ExtraPrepareSeals); n != 0 {
		t.Fatalf("%d extra seals kept", n)
	}
}

// The proposer re-proposes the highest prepared block of the ROUND-CHANGEs
// without validating it.
func TestRefReproposalNotValidated(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.roundTimeout() // (10, 1), node 1 is the proposer
	b := h.proposal(1)
	h.env.invalid[blockHash(b)] = true
	ps := []*codec.Message{h.prepare(0, view(10, 0), b), h.prepare(2, view(10, 0), b), h.prepare(3, view(10, 0), b)}
	before := h.env.validateCalls
	h.deliver(0, h.roundChange(0, view(10, 1), roundPtr(0), b, ps))
	h.deliver(2, h.roundChange(2, view(10, 1), nil, nil, nil))
	h.deliver(3, h.roundChange(3, view(10, 1), nil, nil, nil))
	h.expect(Process, rowRCProposed, true)
	bs := h.broadcasts()
	if len(bs) != 1 || bs[0].Msg.Code != codec.CodePreprepare || blockHash(bs[0].Msg.Proposal) != blockHash(b) {
		t.Fatalf("PRE-PREPARE %+v", bs)
	}
	if len(bs[0].Msg.RoundChanges) != 3 || len(bs[0].Msg.Prepares) != 3 {
		t.Fatalf("justification %d %d", len(bs[0].Msg.RoundChanges), len(bs[0].Msg.Prepares))
	}
	if h.env.validateCalls != before {
		t.Fatal("the re-proposed block was validated")
	}
	if h.vars().PreprepareSent.Cmp(types.RoundFromUint64(1)) != 0 {
		t.Fatal("preprepare_sent not set")
	}
}

// Without a block to propose the quorum rule returns ERR (not relayed), and a
// request arriving later does not evaluate the rule again.
func TestRefQuorumWithoutProposal(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.roundTimeout()
	h.selfDeliver(h.broadcasts()[0])
	h.expect(Process, rowRCStored, true)
	h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
	h.deliver(2, h.roundChange(2, view(10, 1), nil, nil, nil))
	h.expect(Process, rowRCNoProposal, false)
	h.step(Request{Block: h.proposal(5)})
	if len(h.broadcasts()) != 0 {
		t.Fatal("the request triggered a PRE-PREPARE")
	}
	if p := h.vars().PendingRequest; p == nil || *p != blockHash(h.proposal(5)) {
		t.Fatal("request not stored")
	}
	h.deliver(3, h.roundChange(3, view(10, 1), nil, nil, nil))
	h.expect(Process, rowRCProposed, true)
}

// A ROUND-CHANGE for a height the node already left is OLD and dropped; no
// other output is produced.
func TestRefLateRoundChangeOfDecidedHeight(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.env.head = h.proposal(1)
	h.step(NewHead{})
	h.deliver(0, h.roundChange(0, view(10, 1), nil, nil, nil))
	h.expect(Old, rowOld, false)
	if len(h.out) != 1 {
		t.Fatalf("outputs %v", h.out)
	}
}

// Round 0 is not capped when the base timeout is above the cap; later rounds
// are.
func TestRefRoundZeroNotCapped(t *testing.T) {
	h := newHarness(t, 4, 1)
	maxS := uint64(4)
	policy := uint64(0)
	h.s = NewState(Options{Self: h.addrs[1], Config: types.NewConfig(types.WBFTParams{
		RequestTimeoutSeconds: 1000, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy, MaxRequestTimeoutSeconds: &maxS,
	}, nil, types.GenesisInit{}, nil)})
	h.start()
	arms := outputsOf[ArmTimer](h.out)
	if len(arms) != 1 || arms[0].Duration != 1000*time.Second {
		t.Fatalf("round 0 timer %+v", arms)
	}
	h.roundTimeout()
	for _, a := range outputsOf[ArmTimer](h.out) {
		if a.Kind == RoundTimer && a.Duration != 4*time.Second {
			t.Fatalf("round 1 timer %v", a.Duration)
		}
		if a.Kind == RetryTimer && a.Duration != 1000*time.Second {
			t.Fatalf("retry timer %v", a.Duration)
		}
	}
}

// The future timer waits the duration the proposal check returns, without a
// cap.
func TestRefFutureWaitUncapped(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.env.future[blockHash(b)] = 90 * time.Hour
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	h.expect(Process, rowPreprepareFuture, false)
	arms := outputsOf[ArmTimer](h.out)
	if len(arms) != 1 || arms[0].Kind != FutureTimer || arms[0].Duration != 90*time.Hour || arms[0].Digest != blockHash(b) {
		t.Fatalf("future timer %+v", arms)
	}
	// Expiry schedules the PRE-PREPARE again; its replay is accepted and
	// relayed with its re-encoding.
	delete(h.env.future, blockHash(b))
	h.step(Timeout{Kind: FutureTimer, Gen: arms[0].Gen})
	sch := outputsOf[Schedule](h.out)
	if len(sch) != 1 {
		t.Fatalf("schedule %v", h.out)
	}
	h.step(sch[0].In)
	h.expect(Process, rowPreprepareAccept, true)
}

// A second, different round-0 PRE-PREPARE of the proposer is INVALID and
// changes nothing; besides its outcome only an EVIDENCE observation of kind
// round0_preprepare is produced.
func TestRefSecondRound0PreprepareInvalid(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.deliver(0, h.preprepare(0, view(10, 0), h.proposal(1), nil, nil))
	h.deliver(0, h.preprepare(0, view(10, 0), h.proposal(2), nil, nil))
	h.expect(Invalid, rowInvalid, false)
	var consensusOut []Output
	var evidence []Event
	for _, o := range h.out {
		if e, ok := o.(Event); ok {
			if e.Record.Kind == event.Evidence {
				evidence = append(evidence, e)
			}
			continue
		}
		consensusOut = append(consensusOut, o)
	}
	if len(consensusOut) != 1 {
		t.Fatalf("outputs %v", consensusOut)
	}
	if len(evidence) != 1 || evidence[0].Record.Fields["kind"] != "round0_preprepare" {
		t.Fatalf("evidence %v", evidence)
	}
}

// A failed lookup of the next validator set leaves an empty set: the node
// sends nothing and no signature verifies.
func TestRefValidatorLookupFailure(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	h.env.vsErr = errors.New("test: lookup failed")
	h.env.head = h.proposal(1)
	h.step(NewHead{})
	h.wantView(11, 0, AcceptRequest)
	if v := h.vars(); v.Proposer != (types.Address{}) {
		t.Fatalf("proposer %x", v.Proposer)
	}
	h.roundTimeout()
	if len(h.broadcasts()) != 0 {
		t.Fatal("sent without being a member")
	}
	h.deliver(0, h.prepare(0, view(11, 1), h.block(11, 1, h.addrs[0])))
	h.expect(ClassNone, rowBadSignature, false)
}

// The result of importing a committed block changes nothing.
func TestRefCommitResultIgnored(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	h.reachCommitted(b)
	before := h.vars()
	h.step(CommitResult{Hash: blockHash(b), Err: errors.New("test: import failed")})
	if len(h.out) != 0 {
		t.Fatalf("outputs %v", h.out)
	}
	after := h.vars()
	if after.State != before.State || after.View.Cmp(before.View) != 0 {
		t.Fatal("state changed")
	}
}

// A replayed message is relayed with its re-encoding, which differs from the
// received bytes for a ROUND-CHANGE whose absent prepared block was an empty
// string.
func TestRefReplayRelaysReencoding(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	rc := h.roundChange(0, view(11, 0), nil, nil, nil)
	enc := h.encode(rc)
	// Replace the absent prepared block (0xc0) by an empty string (0x80).
	content, _, err := splitList(enc)
	if err != nil {
		t.Fatal(err)
	}
	items := listItems(t, content)
	items[1] = []byte{0x80}
	received := encodeList(items...)
	h.step(Message{Code: codec.CodeRoundChange, Payload: received, Peer: h.addrs[0]})
	h.expect(Future, rowBacklogged, false)
	h.env.head = h.proposal(1)
	h.step(NewHead{})
	sch := outputsOf[Schedule](h.out)
	if len(sch) != 1 {
		t.Fatalf("schedule %v", h.out)
	}
	h.step(sch[0].In)
	relays := outputsOf[Relay](h.out)
	if len(relays) != 1 {
		t.Fatalf("relays %v", h.out)
	}
	if string(relays[0].Payload) == string(received) || string(relays[0].Payload) != string(enc) {
		t.Fatal("relayed bytes are not the re-encoding")
	}
}

// A signature with a high S value is accepted.
func TestRefHighSAccepted(t *testing.T) {
	h := newHarness(t, 4, 1)
	h.start()
	b := h.proposal(1)
	pp := h.preprepare(0, view(10, 0), b, nil, nil)
	pp.Signature = highS(t, pp.Signature)
	h.deliver(0, pp)
	h.expect(Process, rowPreprepareAccept, true)
	if a, err := ecdsa.RecoverDataSigner(signingPayload(t, pp), pp.Signature); err != nil || a != h.addrs[0] {
		t.Fatalf("recovered %x %v", a, err)
	}
}
