package sim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func deliveryScenario(t *testing.T) Scenario {
	return Scenario{Seed: 8, Validators: testValidators(t, 4), DefaultLink: Link{Delay: []time.Duration{time.Millisecond}}, Until: Stop{Height: 3, Duration: 10 * time.Second}}
}

func deliverySelector(sc Scenario, peer, receiver, signer int) MessageSelector {
	return MessageSelector{Peer: addrOf(sc.Validators[peer]), Receiver: addrOf(sc.Validators[receiver]), Signer: addrOf(sc.Validators[signer]), Code: codec.CodePrepare, Sequence: "2", Round: "0", Occurrence: 1}
}

func startDeliveryFixture(t *testing.T, sc Scenario) *simulation {
	t.Helper()
	s, err := newSimulation(sc)
	if err != nil {
		t.Fatal(err)
	}
	s.ctx = context.Background()
	for _, n := range s.nodes {
		n.start()
	}
	s.pumpAll()
	return s
}

func selectedPrepare(t *testing.T, sc Scenario, signer int, sequence string) []byte {
	t.Helper()
	height, ok := new(big.Int).SetString(sequence, 10)
	if !ok {
		t.Fatal(sequence)
	}
	payload := signVote(sc.Validators[signer].ECDSA, codec.CodePrepare, types.View{Sequence: types.MustHeightFromBig(height)}, types.Hash{byte(signer + 1)}, []byte("selected-delivery"))
	if len(payload) == 0 {
		t.Fatal("signed prepare missing")
	}
	return payload
}

func deliveryRecords(t *testing.T, s *simulation, node int) []journal.Record {
	t.Helper()
	dir := t.TempDir()
	if err := writeOutput(Output{JournalDir: dir}, s.result()); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(nil, filepath.Join(dir, fmt.Sprintf("%x", s.nodes[node].v.address[:])))
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func receivedSelected(t *testing.T, s *simulation, node int, payloads ...[]byte) []*journal.MsgRec {
	t.Helper()
	var out []*journal.MsgRec
	for _, record := range deliveryRecords(t, s, node) {
		m, ok := record.Body.(*journal.MsgRec)
		if !ok || m.Dir != journal.In {
			continue
		}
		for _, payload := range payloads {
			if bytes.Equal(m.Payload, payload) {
				out = append(out, m)
				break
			}
		}
	}
	return out
}

func TestSelectedMessageDropUsesPeerSignerAndExplicitOccurrence(t *testing.T) {
	sc := deliveryScenario(t)
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: deliverySelector(sc, 0, 1, 2)}}
	s := startDeliveryFixture(t, sc)
	payload := selectedPrepare(t, sc, 2, "2")
	otherSigner := selectedPrepare(t, sc, 3, "2")
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address, s.nodes[3].v.address}, uint64(codec.CodePrepare), payload)
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), otherSigner)
	s.l.runAt(time.Millisecond)
	s.pumpAll()
	if len(receivedSelected(t, s, 1, payload)) != 0 || len(receivedSelected(t, s, 3, payload)) != 1 || len(receivedSelected(t, s, 1, otherSigner)) != 1 {
		t.Fatal("drop escaped selected receiver or signed source")
	}
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), payload)
	s.l.runAt(2 * time.Millisecond)
	s.pumpAll()
	if len(receivedSelected(t, s, 1, payload)) != 1 {
		t.Fatal("second occurrence was also dropped")
	}
	observations, err := s.messageDeliveryResults()
	if err != nil || observations[0].Status != "applied" || observations[0].FirstMatches != 2 || observations[0].First.ReleasedAt != nil || observations[0].First.Capture != 0 {
		t.Fatal(observations, err)
	}
	if sc.MessageChanges[0].First.Signer != addrOf(sc.Validators[2]) {
		t.Fatal("caller selector mutated")
	}
}

func TestSelectedMessageSwapObservesDeliveryAndActualCoreInputOrder(t *testing.T) {
	for _, samePeer := range []bool{true, false} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("same-peer=%v/reverse=%v", samePeer, reverse), func(t *testing.T) {
				sc := deliveryScenario(t)
				first, second := deliverySelector(sc, 0, 1, 2), deliverySelector(sc, 3, 1, 3)
				secondPeer := 3
				if samePeer {
					second.Peer = first.Peer
					secondPeer = 0
				}
				sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageSwap, First: first, Second: &second}}
				s := startDeliveryFixture(t, sc)
				a, b := selectedPrepare(t, sc, 2, "2"), selectedPrepare(t, sc, 3, "2")
				earlyPeer, latePeer, early, late := 0, secondPeer, a, b
				if reverse {
					earlyPeer, latePeer, early, late = secondPeer, 0, b, a
				}
				s.nodes[earlyPeer].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), early)
				s.l.runAt(time.Millisecond)
				s.pumpAll()
				if len(receivedSelected(t, s, 1, a, b)) != 0 {
					t.Fatal("first arrival not held")
				}
				s.l.runAt(2 * time.Millisecond)
				s.nodes[latePeer].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), late)
				s.l.runAt(3 * time.Millisecond)
				s.pumpAll()
				received := receivedSelected(t, s, 1, a, b)
				if len(received) != 2 || !bytes.Equal(received[0].Payload, late) || !bytes.Equal(received[1].Payload, early) || received[0].Mono != 3*time.Millisecond || received[1].Mono != received[0].Mono {
					t.Fatal("wire delivery order or causal time differs", received)
				}
				wanted := map[uint64]bool{received[0].Capture: true, received[1].Capture: true}
				var steps []uint64
				for _, record := range deliveryRecords(t, s, 1) {
					step, ok := record.Body.(*journal.StepRec)
					if !ok || step.InputKind != inputlog.KindCapturedMessage {
						continue
					}
					capture, err := inputlog.CapturedReference(step.Input)
					if err != nil {
						t.Fatal(err)
					}
					if wanted[capture] {
						steps = append(steps, capture)
					}
				}
				wantSteps := []uint64{received[0].Capture, received[1].Capture}
				if !samePeer {
					// Manual receive checks select a seeded peer, not a global
					// FIFO. Do not bypass that policy to force core input order.
					wantSteps[0], wantSteps[1] = wantSteps[1], wantSteps[0]
				}
				if !reflect.DeepEqual(steps, wantSteps) {
					t.Fatal("actual core input policy changed", steps, wantSteps)
				}
				observations, err := s.messageDeliveryResults()
				if err != nil || observations[0].Status != "applied" {
					t.Fatal(observations, err)
				}
				x, y := observations[0].First, observations[0].Second
				if reverse {
					x, y = y, x
				}
				if x.ArrivalOrder >= y.ArrivalOrder || x.ReleaseOrder <= y.ReleaseOrder || *x.ReleasedAt < x.SentAt || *y.ReleasedAt < y.SentAt || y.SentAt != 2*time.Millisecond {
					t.Fatal("observed order or causality invalid", x, y)
				}
			})
		}
	}
}

func TestSelectedMessageRunAppliesDropAndRetainsIncompletePair(t *testing.T) {
	sc := deliveryScenario(t)
	dir := t.TempDir()
	baseline, err := Run(context.Background(), sc, Output{JournalDir: dir})
	if err != nil || len(baseline.Violations) != 0 {
		t.Fatal(err, baseline.Violations)
	}
	records, err := journal.ReadAll(nil, filepath.Join(dir, fmt.Sprintf("%x", addrOf(sc.Validators[1]))))
	if err != nil {
		t.Fatal(err)
	}
	var selector MessageSelector
	for _, record := range records {
		m, ok := record.Body.(*journal.MsgRec)
		if !ok || m.Dir != journal.In || m.Code != uint64(codec.CodePrepare) {
			continue
		}
		v, err := consensus.Recover(codec.Code(m.Code), m.Payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		selector = MessageSelector{Peer: addrOf(sc.Validators[m.PeerIdx]), Receiver: addrOf(sc.Validators[1]), Signer: v.Source, Code: v.Msg.Code, Sequence: v.Msg.View.Sequence.String(), Round: v.Msg.View.Round.String(), Occurrence: 1}
		break
	}
	if selector.Occurrence == 0 {
		t.Fatal("baseline contains no eligible prepare")
	}
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: selector}}
	dropped, err := Run(context.Background(), sc, Output{})
	if err != nil || dropped.MessageDeliveries[0].Status != "applied" || len(dropped.Violations) != 0 {
		t.Fatal("selected baseline message not dropped", err, dropped)
	}
	missing := selector
	missing.Sequence = "999"
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageSwap, First: selector, Second: &missing}}
	partial, err := Run(context.Background(), sc, Output{})
	if !errors.Is(err, ErrMessageSelection) || partial == nil {
		t.Fatal("missing pair reported success", err)
	}
	observation := partial.MessageDeliveries[0]
	if observation.Status != "incomplete_pair" || observation.First == nil || observation.Second != nil || observation.First.ReleasedAt != nil || observation.First.Capture != 0 {
		t.Fatal("missing pair invented a release", observation)
	}
}

func TestSelectedMessageSwapDoesNotCrossReceiverIncarnations(t *testing.T) {
	sc := deliveryScenario(t)
	first, second := deliverySelector(sc, 0, 1, 2), deliverySelector(sc, 3, 1, 3)
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageSwap, First: first, Second: &second}}
	s := startDeliveryFixture(t, sc)
	a, b := selectedPrepare(t, sc, 2, "2"), selectedPrepare(t, sc, 3, "2")
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), a)
	s.l.runAt(time.Millisecond)
	s.nodes[1].stop()
	s.nodes[1].start()
	s.pumpAll()
	s.nodes[3].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), b)
	s.l.runAt(2 * time.Millisecond)
	s.pumpAll()
	observations, err := s.messageDeliveryResults()
	if !errors.Is(err, ErrMessageSelection) || observations[0].Status != "receiver_incarnation_changed" || observations[0].First.ReleasedAt != nil || observations[0].First.ReceiverRun == observations[0].Second.ReceiverRun {
		t.Fatal("old packet crossed restart", observations, err)
	}
	if len(receivedSelected(t, s, 1, a)) != 0 || len(receivedSelected(t, s, 1, b)) != 1 {
		t.Fatal("old packet delivered or current packet lost")
	}
}

func TestSelectedMessageSwapCopiesCallerSelectorsAndReversesEqualTimeArrivals(t *testing.T) {
	sc := deliveryScenario(t)
	first, second := deliverySelector(sc, 0, 1, 2), deliverySelector(sc, 0, 1, 3)
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageSwap, First: first, Second: &second}}
	s := startDeliveryFixture(t, sc)
	// The running scenario owns both its slice and the optional selector.
	sc.MessageChanges[0].First.Sequence = "999"
	sc.MessageChanges[0].Kind = MessageDrop
	second.Signer = types.Address{}
	a, b := selectedPrepare(t, sc, 2, "2"), selectedPrepare(t, sc, 3, "2")
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), a)
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), b)
	s.l.runAt(time.Millisecond)
	s.pumpAll()
	received := receivedSelected(t, s, 1, a, b)
	observations, err := s.messageDeliveryResults()
	if err != nil || len(received) != 2 || !bytes.Equal(received[0].Payload, b) || !bytes.Equal(received[1].Payload, a) || observations[0].First.EligibleAt != observations[0].Second.EligibleAt || observations[0].Change.Kind != MessageSwap || observations[0].Change.Second.Signer == (types.Address{}) {
		t.Fatal("snapshot or equal-time insertion order lost", observations, err)
	}
}

func TestSelectedMessageRoundDoesNotTruncateAt64Bits(t *testing.T) {
	sc := deliveryScenario(t)
	round, err := types.RoundFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 80), big.NewInt(7)))
	if err != nil {
		t.Fatal(err)
	}
	selector := deliverySelector(sc, 0, 1, 2)
	selector.Round = round.String()
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: selector}}
	s := startDeliveryFixture(t, sc)
	small := selectedPrepare(t, sc, 2, "2")
	large := signVote(sc.Validators[2].ECDSA, codec.CodePrepare, types.View{Sequence: types.HeightFromUint64(2), Round: round}, types.Hash{3}, []byte("selected-delivery"))
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), small)
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), large)
	s.l.runAt(time.Millisecond)
	observations, err := s.messageDeliveryResults()
	if err != nil || observations[0].FirstMatches != 1 || len(receivedSelected(t, s, 1, small)) != 1 || len(receivedSelected(t, s, 1, large)) != 0 {
		t.Fatal("large round alias or lost match", observations, err)
	}
}

func TestSelectedMessageMissingRetainsUnchangedRunAndOutput(t *testing.T) {
	sc := deliveryScenario(t)
	baseline, err := Run(context.Background(), sc, Output{})
	if err != nil {
		t.Fatal(err)
	}
	selector := deliverySelector(sc, 0, 1, 2)
	selector.Sequence = "999"
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: selector}}
	dir := t.TempDir()
	result, err := Run(context.Background(), sc, Output{JournalDir: dir})
	if !errors.Is(err, ErrMessageSelection) || result == nil || result.MessageDeliveries[0].First != nil || result.MessageDeliveries[0].Status != "unmatched" {
		t.Fatal("missing selector reported success", err, result)
	}
	result.MessageDeliveries = nil
	if !reflect.DeepEqual(result, baseline) {
		t.Fatal("inactive selection changed unrelated execution or random draws")
	}
	if _, _, err := ReadJournalDir(dir); err != nil {
		t.Fatal("partial run output was not retained", err)
	}
}

func TestSelectedMessageFullWidthViewAndUnavailableArrival(t *testing.T) {
	sc := deliveryScenario(t)
	selector := deliverySelector(sc, 0, 1, 2)
	selector.Sequence = "18446744073709551618"
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: selector}}
	s := startDeliveryFixture(t, sc)
	payload := selectedPrepare(t, sc, 2, selector.Sequence)
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), payload)
	s.l.runAt(time.Millisecond)
	observation, err := s.messageDeliveryResults()
	if err != nil || observation[0].First == nil || len(receivedSelected(t, s, 1, payload)) != 0 {
		t.Fatal("full-width selector did not match", observation, err)
	}
	sc.Partitions = []Partition{{From: 0, To: time.Second, DirectedCut: [][2]types.Address{{selector.Peer, selector.Receiver}}}}
	s = startDeliveryFixture(t, sc)
	s.nodes[0].tr.Send([]types.Address{s.nodes[1].v.address}, uint64(codec.CodePrepare), payload)
	s.l.runAt(time.Millisecond)
	observation, err = s.messageDeliveryResults()
	if !errors.Is(err, ErrMessageSelection) || observation[0].First != nil || observation[0].FirstMatches != 0 {
		t.Fatal("cut link invented a selection receipt", observation, err)
	}
}

func TestSelectedMessageRejectsMalformedAndOverlappingSelectors(t *testing.T) {
	sc := deliveryScenario(t)
	valid := MessageDeliveryChange{Kind: MessageDrop, First: deliverySelector(sc, 0, 1, 2)}
	for _, mutate := range []func(*MessageDeliveryChange){
		func(c *MessageDeliveryChange) { c.Kind = "inject" },
		func(c *MessageDeliveryChange) { c.First.Occurrence = 0 },
		func(c *MessageDeliveryChange) { c.First.Sequence = "02" },
		func(c *MessageDeliveryChange) { c.First.Sequence = "0" },
		func(c *MessageDeliveryChange) { c.First.Round = "-1" },
		func(c *MessageDeliveryChange) { c.First.Code = codec.CodeIstanbul },
		func(c *MessageDeliveryChange) { c.First.Signer = types.Address{} },
		func(c *MessageDeliveryChange) { c.First.Receiver = c.First.Peer },
		func(c *MessageDeliveryChange) { c.Kind = MessageSwap },
		func(c *MessageDeliveryChange) { copy := c.First; c.Second = &copy },
		func(c *MessageDeliveryChange) { copy := c.First; c.Kind, c.Second = MessageSwap, &copy },
		func(c *MessageDeliveryChange) {
			copy := c.First
			copy.Receiver = addrOf(sc.Validators[3])
			c.Kind, c.Second = MessageSwap, &copy
		},
	} {
		change := valid
		mutate(&change)
		sc.MessageChanges = []MessageDeliveryChange{change}
		if _, err := newSimulation(sc); !errors.Is(err, ErrScenario) {
			t.Fatal("invalid message change accepted", change, err)
		}
	}
	sc.MessageChanges = []MessageDeliveryChange{valid, valid}
	if _, err := newSimulation(sc); !errors.Is(err, ErrScenario) {
		t.Fatal("overlapping declarations accepted", err)
	}
}

func TestSelectedMessagePreservesTransportFrameRejection(t *testing.T) {
	sc := deliveryScenario(t)
	selector := deliverySelector(sc, 0, 1, 2)
	sc.MessageChanges = []MessageDeliveryChange{{Kind: MessageDrop, First: selector}}
	s := startDeliveryFixture(t, sc)
	message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(2)}, Seal: make([]byte, transport.MaxFramePayload)}
	key, err := ecdsa.PrivateKeyFromBytes(sc.Validators[2].ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.SigningPayload(message, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature, err = ecdsa.SignData(signed, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.Recover(codec.CodePrepare, payload, nil); err != nil || len(payload) <= transport.MaxFramePayload {
		t.Fatal("frame boundary positive control invalid", err)
	}
	capture := s.nodes[1].capture
	s.selectDelivery(s.nodes[1], selector.Peer, uint64(codec.CodePrepare), payload, 0, s.nodes[0].runID())
	observations, err := s.messageDeliveryResults()
	if !errors.Is(err, ErrMessageSelection) || observations[0].First != nil || s.nodes[1].capture != capture+1 {
		t.Fatal("message selection swallowed the original frame verdict", observations, err)
	}
}
