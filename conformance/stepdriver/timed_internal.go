package stepdriver

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/0xmhha/wbft/types"
	"sort"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

var ErrTraceSigningUnavailable = errors.New("stepdriver: recorded signing result unavailable for generated broadcast")

// TimedError identifies an execution failure without assigning generated input
// a fictitious source step. ParentExecution is the output that reserved it.
type TimedError struct {
	Execution       uint64
	Source          *TimedSource
	Cause           *TimedSource
	ParentExecution uint64
	ParentOutput    uint64
	Err             error
}

func (e *TimedError) Error() string {
	return fmt.Sprintf("stepdriver: timed execution %d parent %d: %v", e.Execution, e.ParentExecution, e.Err)
}
func (e *TimedError) Unwrap() error { return e.Err }

type timedOutputKey struct {
	Source TimedSource
	Output int
}
type timedSigningEvidence struct {
	Output consensus.Broadcast
	Input  consensus.Input
	Source TimedSource
}
type timedInternal struct {
	Input           consensus.Input
	Broadcast       *consensus.Broadcast
	Cause           *TimedSource
	ParentExecution uint64
	ParentOutput    uint64
	Evidence        *TimedSource
}

// unsignedOwn removes only the signature and seal the runner adds. Signed
// nested certificates remain byte-identical; they cannot be reconstructed.
func unsignedOwn(m *codec.Message) ([]byte, error) {
	if m == nil {
		return nil, ErrTraceInvalidInput
	}
	copy := *m
	copy.Signature, copy.Seal = nil, nil
	return codec.EncodeMessage(&copy)
}
func matchesInternal(output consensus.Output, in consensus.Input) (bool, error) {
	switch o := output.(type) {
	case consensus.Schedule:
		if inputlog.Kind(o.In) != inputlog.Kind(in) {
			return false, nil
		}
		a, err := inputlog.Encode(o.In)
		if err != nil {
			return false, err
		}
		b, err := inputlog.Encode(in)
		return err == nil && bytes.Equal(a, b), err
	case consensus.Broadcast:
		switch v := in.(type) {
		case consensus.Message:
			m, err := codec.DecodeMessage(v.Code, v.Payload)
			if err != nil {
				return false, err
			}
			a, err := unsignedOwn(o.Msg)
			if err != nil {
				return false, err
			}
			b, err := unsignedOwn(m)
			return err == nil && bytes.Equal(a, b), err
		case consensus.BroadcastFailed:
			return o.Msg != nil && o.Msg.Code == v.Code && o.Msg.View.Sequence.Cmp(v.View.Sequence) == 0 && o.Msg.View.Round.Cmp(v.View.Round) == 0, nil
		}
	}
	return false, nil
}
func sameBroadcast(a, b consensus.Broadcast) bool {
	x, e := inputlog.EncodeOutputs([]consensus.Output{a})
	if e != nil {
		return false
	}
	y, e := inputlog.EncodeOutputs([]consensus.Output{b})
	return e == nil && bytes.Equal(x, y)
}

// Signing results are conditional source evidence, not a newly executed signer.
// Reuse requires the complete original Broadcast request and source context,
// preserves recorded signing order, and never edits nested certificates.
type timedSigningKey struct {
	Writer string
	Engine uint64
	Head   types.Hash
	Output [32]byte
}
type timedSigningPool struct {
	origins  map[TimedSource]timedOutputKey
	byOutput map[timedOutputKey]timedSigningEvidence
	entries  map[timedSigningKey][]timedSigningEvidence
	used     map[TimedSource]bool
	last     map[answerCoordinate]uint64
}

func newTimedSigningPool(proofs map[timedOutputKey]timedSigningEvidence, source map[TimedSource]timedSourceEntry) (*timedSigningPool, error) {
	p := &timedSigningPool{origins: map[TimedSource]timedOutputKey{}, byOutput: proofs, entries: map[timedSigningKey][]timedSigningEvidence{}, used: map[TimedSource]bool{}, last: map[answerCoordinate]uint64{}}
	for key, proof := range proofs {
		entry, ok := source[key.Source]
		if !ok {
			return nil, ErrTraceScheduleReservation
		}
		raw, err := inputlog.EncodeOutputs([]consensus.Output{proof.Output})
		if err != nil {
			return nil, err
		}
		index := timedSigningKey{key.Source.Writer, key.Source.Engine, entry.record.HeadHash, sha256.Sum256(raw)}
		if _, exists := p.origins[proof.Source]; exists {
			return nil, ErrTraceScheduleReservation
		}
		p.origins[proof.Source] = key
		p.entries[index] = append(p.entries[index], proof)
	}
	for key, proofs := range p.entries {
		sort.Slice(proofs, func(i, j int) bool { return proofs[i].Source.Ordinal < proofs[j].Source.Ordinal })
		p.entries[key] = proofs
	}
	return p, nil
}
func (p *timedSigningPool) take(out consensus.Broadcast, writer string, engine uint64, head types.Hash) (timedSigningEvidence, bool, error) {
	raw, err := inputlog.EncodeOutputs([]consensus.Output{out})
	if err != nil {
		return timedSigningEvidence{}, false, err
	}
	key := timedSigningKey{writer, engine, head, sha256.Sum256(raw)}
	var selected *timedSigningEvidence
	var encoded []byte
	order := answerCoordinate{writer: writer, engine: engine}
	for _, proof := range p.entries[key] {
		if p.used[proof.Source] || proof.Source.Ordinal < p.last[order] || !sameBroadcast(out, proof.Output) {
			continue
		}
		value, err := inputlog.Encode(proof.Input)
		if err != nil {
			return timedSigningEvidence{}, false, err
		}
		// Self-receipt clock is execution data. Compare the original signature bytes,
		// not receipt time, when checking conflicting signing results.
		if m, ok := proof.Input.(consensus.Message); ok {
			value = m.Payload
		}
		if selected != nil && (inputlog.Kind(selected.Input) != inputlog.Kind(proof.Input) || !bytes.Equal(encoded, value)) {
			return timedSigningEvidence{}, false, ErrTraceSigningUnavailable
		}
		if selected == nil {
			copy := proof
			selected = &copy
			encoded = value
		}
	}
	if selected == nil {
		return timedSigningEvidence{}, false, nil
	}
	p.used[selected.Source] = true
	p.last[order] = selected.Source.Ordinal
	return *selected, true, nil
}
