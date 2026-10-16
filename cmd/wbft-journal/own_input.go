package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type ownMessageKey struct {
	code uint64
	key  types.Hash
}

type ownInput struct {
	outcome, input, engine, step uint64
	code                         uint64
	key                          types.Hash
	payload                      []byte
	position                     wal.Position
	encodedInput                 [32]byte
}

type ownRun struct {
	node     types.Address
	bad      bool
	outcomes map[uint64]*ownInput
	inputs   map[uint64]*ownInput
	messages map[ownMessageKey]*ownInput // nil means multiple witnesses
}

type ownOutcome struct {
	seq uint64
	rec *journal.OutcomeRec
}

// indexOwnInputs proves byte provenance, not which asynchronous send call
// produced a wire write. Only a unique accepted, signed internal message
// can explain an otherwise unlinked relay. Gaps invalidate the whole run.
// A second pass is needed because outcomes and writes precede their step.
func (w *r01Writer) indexOwnInputs(fs fsys.FS, dir string) map[string]*ownRun {
	runs := map[string]*ownRun{}
	stream := sha256.New()
	encoder := json.NewEncoder(stream)
	var encodeErr error
	var current *ownRun
	var head *types.Height
	var pending []ownOutcome
	seen := map[[2]uint64]bool{}
	inRange := func() bool {
		if head == nil {
			return w.from == nil
		}
		h := head.AddUint64(1)
		return (w.from == nil || h.Cmp(*w.from) >= 0) && (w.to == nil || h.Cmp(*w.to) <= 0)
	}
	err := scan(fs, dir, func(rec journal.Record, pos wal.Position) {
		if encodeErr != nil {
			return
		}
		encodeErr = encodeOwnStream(encoder, rec, pos)
		if encodeErr != nil {
			return
		}
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			if current != runs[b.Run] || current == nil {
				current = runs[b.Run]
				if current == nil {
					current = &ownRun{node: b.Self, outcomes: map[uint64]*ownInput{}, inputs: map[uint64]*ownInput{}, messages: map[ownMessageKey]*ownInput{}}
					runs[b.Run] = current
				} else {
					current.bad = true // a writer run reappeared after another run
				}
				pending, head, seen = nil, nil, map[[2]uint64]bool{}
			}
			if current.node != b.Self {
				current.bad = true
			}
		case *journal.GapRec:
			if current != nil {
				current.bad = true
			}
			pending = nil
		case *journal.OutcomeRec:
			if current != nil && inRange() && b.EngineRun != 0 && b.Step != 0 && !b.AtOffer && b.Of == 0 &&
				b.Via == "self" && b.Peer == current.node && b.Outcome == event.Accept && b.Check == "PROCESS" {
				if len(pending) >= outcomeLinkWindow {
					current.bad = true
					pending = nil
				} else {
					pending = append(pending, ownOutcome{seq: rec.JSeq, rec: b})
				}
			}
		case *journal.StepRec:
			h := b.HeadNumber
			head = &h
			candidates := pending
			pending = nil // never cross a different core input
			if current == nil {
				return
			}
			scope := [2]uint64{b.EngineRun, b.Step}
			if seen[scope] {
				current.bad = true
			}
			seen[scope] = true
			if !inRange() || b.EngineRun == 0 || b.Step == 0 || b.Via != "internal" || b.InputKind != inputlog.KindMessage {
				return
			}
			input, err := inputlog.Decode(b.InputKind, b.Input, nil)
			if err != nil {
				return
			}
			msg, ok := input.(consensus.Message)
			if !ok || msg.Peer != current.node {
				return
			}
			verified, err := consensus.Recover(msg.Code, msg.Payload, nil)
			if err != nil || verified.Source != current.node {
				return
			}
			key := codec.DedupKey(msg.Payload)
			var accepted *ownOutcome
			for i := range candidates {
				o := &candidates[i]
				if o.seq >= rec.JSeq || o.rec.EngineRun != b.EngineRun || o.rec.Step != b.Step || o.rec.Code != uint64(msg.Code) || o.rec.DedupKey != key {
					continue
				}
				if accepted != nil {
					return // conflicting outcomes are not a unique witness
				}
				accepted = o
			}
			if accepted == nil {
				return
			}
			x := &ownInput{outcome: accepted.seq, input: rec.JSeq, engine: b.EngineRun, step: b.Step, code: uint64(msg.Code), key: key,
				payload: bytes.Clone(msg.Payload), position: pos, encodedInput: sha256.Sum256(b.Input)}
			current.outcomes[x.outcome], current.inputs[x.input] = x, x
			k := ownMessageKey{x.code, x.key}
			if _, exists := current.messages[k]; exists {
				current.messages[k] = nil
			} else {
				current.messages[k] = x
			}
		}
	})
	if err != nil || encodeErr != nil {
		return nil // the normal export pass reports the damaged prefix
	}
	w.ownStream = ownStreamSum(stream)
	return runs
}

func (w *r01Writer) ownRun() *ownRun {
	if w.run != nil {
		x := w.own[w.run.Run]
		if x != nil && !x.bad && x.node == w.node {
			return x
		}
	}
	return nil
}

func (w *r01Writer) ownInputRecord(seq uint64, b *journal.StepRec, pos wal.Position) error {
	run := w.ownRun()
	if run == nil || run.inputs[seq] == nil {
		return nil
	}
	x := run.inputs[seq]
	if b.EngineRun != x.engine || b.Step != x.step || b.Via != "internal" || b.InputKind != inputlog.KindMessage || pos != x.position || sha256.Sum256(b.Input) != x.encodedInput {
		return fmt.Errorf("own input source changed between export passes")
	}
	sum, err := w.payload(x.payload)
	if err != nil {
		return err
	}
	r := w.common("own_input", seq)
	r["via"], r["input_kind"] = "internal", inputlog.KindMessage
	r["engine_run"], r["step"] = x.engine, x.step
	r["code"], r["peer"], r["dedup_key"] = fmt.Sprintf("%#x", x.code), hexAddr(w.node), hexHash(x.key)
	r["payload_sha256"], r["size"] = sum, len(x.payload)
	r["journal_segment"], r["journal_offset"] = pos.Segment, pos.Offset
	return w.write(r)
}

// ownMessage links only unique exact own bytes. relay_of remains reserved
// for received frames, including the existing late-receipt path.
func (w *r01Writer) ownMessage(r map[string]any, b *journal.MsgRec) bool {
	run := w.ownRun()
	if run == nil {
		return false
	}
	x := run.messages[ownMessageKey{b.Code, b.DedupKey}]
	if x == nil || !bytes.Equal(x.payload, b.Payload) || b.Size > uint64(len(b.Payload)) {
		return false
	}
	r["own_message_of"] = x.outcome
	return true
}

func encodeOwnStream(encoder *json.Encoder, rec journal.Record, pos wal.Position) error {
	// Decoded journal bodies consist only of supported JSON field types.
	// Include the physical position to detect moving or replaced sources.
	return encoder.Encode(struct {
		Position wal.Position
		Record   journal.Record
	}{pos, rec})
}

func ownStreamSum(h hash.Hash) [32]byte { var sum [32]byte; copy(sum[:], h.Sum(nil)); return sum }

func (w *r01Writer) hasOwnEvidence() bool {
	for _, run := range w.own {
		if !run.bad && len(run.inputs) > 0 {
			return true
		}
	}
	return false
}
