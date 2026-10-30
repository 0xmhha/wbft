package sim

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

const (
	MessageDrop = "drop"
	MessageSwap = "swap"
)

// MessageSelector identifies one eligible transport delivery, before receiver
// Offer. Peer is the relay, Signer is the signed source, and Occurrence is
// one-based among deliveries of the same tuple across receiver incarnations.
// Sequence and Round are canonical decimal strings, without a uint64 truncation.
type MessageSelector struct {
	Peer, Receiver, Signer types.Address
	Code                   codec.Code
	Sequence, Round        string
	Occurrence             uint64
}

// MessageDeliveryChange drops one delivery or reverses a pair's relative
// delivery order at one receiver. Swap holds whichever selection arrives first
// until the other actually arrives. It never moves a delivery before its send.
type MessageDeliveryChange struct {
	Kind   string
	First  MessageSelector
	Second *MessageSelector
}

// SelectedMessageDelivery is observed execution evidence. EligibleAt is the
// transport callback, not a received journal record. Capture and Offer are set
// only by an actual receiver invocation. Release order does not assert that a
// message passed dedup, signature checks, or the core handler.
type SelectedMessageDelivery struct {
	SentAt, EligibleAt   time.Duration
	ReleasedAt           *time.Duration
	PeerRun, ReceiverRun string
	PayloadSHA256        types.Hash
	ArrivalOrder         uint64
	ReleaseOrder         uint64
	Capture              uint64
	Offer                string
}

type MessageDeliveryObservation struct {
	Change                      MessageDeliveryChange
	Status                      string
	First, Second               *SelectedMessageDelivery
	FirstMatches, SecondMatches uint64
}

// ErrMessageSelection is returned with the retained Result and output when a
// declared change cannot be applied. Missing pairs never become silent success.
var ErrMessageSelection = errors.New("sim: selected message delivery was not applied")

type deliveryTuple struct {
	peer, receiver, signer types.Address
	code                   codec.Code
	sequence, round        string
}

func (m MessageSelector) tuple() deliveryTuple {
	return deliveryTuple{m.Peer, m.Receiver, m.Signer, m.Code, m.Sequence, m.Round}
}

type deliveryRoute struct {
	peer, receiver types.Address
	code           codec.Code
}

type deliverySlot struct{ change, side int }
type occurrenceKey struct {
	tuple      deliveryTuple
	occurrence uint64
}
type selectedPacket struct {
	dst      *node
	inc      int
	peer     types.Address
	code     uint64
	payload  []byte
	evidence *SelectedMessageDelivery
}
type deliveryState struct {
	observation MessageDeliveryObservation
	held        *selectedPacket
}
type messageDeliveryControl struct {
	states             []deliveryState
	slots              map[occurrenceKey]deliverySlot
	routes             map[deliveryRoute]bool
	tuples             map[deliveryTuple]bool
	counts             map[deliveryTuple]uint64
	arrivals, releases uint64
}

func canonicalUnsigned(s string, positive bool) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && (!positive || n.Sign() > 0) && n.String() == s
}

func (s *simulation) newMessageDeliveryControl() error {
	if len(s.sc.MessageChanges) == 0 {
		return nil
	}
	if len(s.sc.MessageChanges) > 4096 {
		return fmt.Errorf("%w: too many message changes", ErrScenario)
	}
	m := &messageDeliveryControl{states: make([]deliveryState, len(s.sc.MessageChanges)), slots: map[occurrenceKey]deliverySlot{}, routes: map[deliveryRoute]bool{}, tuples: map[deliveryTuple]bool{}, counts: map[deliveryTuple]uint64{}}
	s.sc.MessageChanges = slices.Clone(s.sc.MessageChanges)
	for i, c := range s.sc.MessageChanges {
		if c.Kind != MessageDrop && c.Kind != MessageSwap || (c.Kind == MessageSwap) != (c.Second != nil) {
			return fmt.Errorf("%w: invalid message change kind or pair", ErrScenario)
		}
		selectors := []MessageSelector{c.First}
		if c.Second != nil {
			copy := *c.Second
			c.Second = &copy
			if copy.Receiver != c.First.Receiver {
				return fmt.Errorf("%w: swap needs one receiver", ErrScenario)
			}
			selectors = append(selectors, copy)
		}
		for side, selector := range selectors {
			if s.byAddr[selector.Peer] == nil || s.byAddr[selector.Receiver] == nil || s.byAddr[selector.Signer] == nil || selector.Peer == selector.Receiver || selector.Code < codec.CodePreprepare || selector.Code > codec.CodeRoundChange || selector.Occurrence == 0 || !canonicalUnsigned(selector.Sequence, true) || !canonicalUnsigned(selector.Round, false) {
				return fmt.Errorf("%w: invalid message selector", ErrScenario)
			}
			key := occurrenceKey{selector.tuple(), selector.Occurrence}
			if _, duplicate := m.slots[key]; duplicate {
				return fmt.Errorf("%w: overlapping message selectors", ErrScenario)
			}
			m.slots[key] = deliverySlot{i, side}
			m.tuples[selector.tuple()] = true
			m.routes[deliveryRoute{selector.Peer, selector.Receiver, selector.Code}] = true
		}
		s.sc.MessageChanges[i] = c
		m.states[i].observation = MessageDeliveryObservation{Change: c, Status: "pending"}
	}
	s.messages = m
	return nil
}

// selectDelivery runs only after the original loss/delay/partition callback and
// incarnation checks. It consumes no random draws and cannot intercept block
// propagation or state synchronisation, which do not pass through sendOne.
func (s *simulation) selectDelivery(dst *node, peer types.Address, code uint64, payload []byte, sent time.Duration, peerRun string) {
	m := s.messages
	if m == nil || !m.routes[deliveryRoute{peer, dst.v.address, codec.Code(code)}] {
		dst.receive(peer, code, payload)
		return
	}
	_, _, action, _ := transport.DecodeFrame(code, payload)
	if action != transport.FrameDeliver {
		dst.receive(peer, code, payload)
		return
	}
	domain, err := types.DomainForConfig(dst.cfg, codec.BlockHash(s.genesis.Header))
	if err != nil {
		dst.receive(peer, code, payload)
		return
	}
	verified, err := consensus.RecoverWithDomain(codec.Code(code), payload, nil, domain)
	if err != nil {
		dst.receive(peer, code, payload)
		return
	}
	tuple := deliveryTuple{peer, dst.v.address, verified.Source, verified.Msg.Code, verified.Msg.View.Sequence.String(), verified.Msg.View.Round.String()}
	if !m.tuples[tuple] {
		dst.receive(peer, code, payload)
		return
	}
	m.counts[tuple]++
	slot, selected := m.slots[occurrenceKey{tuple, m.counts[tuple]}]
	if !selected {
		dst.receive(peer, code, payload)
		return
	}
	m.arrivals++
	hash := sha256.Sum256(payload)
	evidence := &SelectedMessageDelivery{SentAt: sent, EligibleAt: s.l.c.Mono(), PeerRun: peerRun, ReceiverRun: dst.runID(), PayloadSHA256: types.Hash(hash), ArrivalOrder: m.arrivals}
	packet := &selectedPacket{dst: dst, inc: dst.inc, peer: peer, code: code, payload: bytes.Clone(payload), evidence: evidence}
	state := &m.states[slot.change]
	if slot.side == 0 {
		state.observation.First = evidence
	} else {
		state.observation.Second = evidence
	}
	if state.observation.Change.Kind == MessageDrop {
		state.observation.Status = "applied"
		return
	}
	if state.held == nil {
		state.held = packet
		return
	}
	held := state.held
	state.held = nil
	if !held.dst.alive || held.dst.inc != held.inc || held.dst.r == nil {
		state.observation.Status = "receiver_incarnation_changed"
		m.release(s, packet)
		return
	}
	// Both arrivals have already occurred. The later arrival is offered first;
	// only receiver delivery order changes, never either wire payload.
	firstOK := m.release(s, packet)
	secondOK := m.release(s, held)
	state.observation.Status = "applied"
	if !firstOK || !secondOK {
		state.observation.Status = "receiver_offer_refused"
	}
}

func (m *messageDeliveryControl) release(s *simulation, packet *selectedPacket) bool {
	if !packet.dst.alive || packet.dst.inc != packet.inc || packet.dst.r == nil {
		return false
	}
	m.releases++
	at := s.l.c.Mono()
	packet.evidence.ReleasedAt = &at
	packet.evidence.ReleaseOrder = m.releases
	packet.evidence.Capture, packet.evidence.Offer = packet.dst.receive(packet.peer, packet.code, packet.payload)
	return packet.evidence.Offer == "queued"
}

func (s *simulation) messageDeliveryResults() ([]MessageDeliveryObservation, error) {
	if s.messages == nil {
		return nil, nil
	}
	out := make([]MessageDeliveryObservation, len(s.messages.states))
	var firstError error
	for i, state := range s.messages.states {
		observation := state.observation
		observation.FirstMatches = s.messages.counts[observation.Change.First.tuple()]
		if observation.Change.Second != nil {
			observation.SecondMatches = s.messages.counts[observation.Change.Second.tuple()]
		}
		if observation.Status == "pending" {
			observation.Status = "unmatched"
			if state.held != nil {
				observation.Status = "incomplete_pair"
			}
		}
		if observation.Status != "applied" && firstError == nil {
			firstError = fmt.Errorf("%w: change %d: %s", ErrMessageSelection, i, observation.Status)
		}
		out[i] = observation
	}
	return out, firstError
}
