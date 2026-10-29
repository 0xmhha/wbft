package runner

import (
	"errors"
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// validatorHistoryWriter is exclusively owned by the core actor. Its normal
// ledger excludes the bounded terminal reserve inside the same hard cap.
type validatorHistoryWriter struct {
	limits     ValidatorHistoryLimits
	budget     *validatorHistoryBudget
	prefix     validatorHistoryReplay
	write      func(wal.Record, bool) (wal.Position, error)
	step       *validatorHistoryStep
	footer     validatorHistoryControl
	footerKind uint8
	terminal   bool
	timers     [5]*consensus.ArmTimer
	installed  [5]*consensus.ArmTimer
	sent       map[ownKey][]byte
}

func newValidatorHistoryWriter(cfg Config, retained []wal.Record, replay *validatorHistoryReplay, write func(wal.Record, bool) (wal.Position, error)) (*validatorHistoryWriter, error) {
	limits, err := validatorHistoryLimits(cfg.ValidatorHistory)
	if err != nil {
		return nil, err
	}
	if write == nil || limits.Bytes <= validatorHistoryHaltBytes || limits.Records <= validatorHistoryHaltCount {
		return nil, errValidatorHistoryBudget
	}
	normal := ValidatorHistoryLimits{Bytes: limits.Bytes - validatorHistoryHaltBytes, Records: limits.Records - validatorHistoryHaltCount}
	budget, err := newValidatorHistoryBudget(normal, retained)
	if err != nil {
		return nil, err
	}
	w := &validatorHistoryWriter{limits: limits, budget: budget, write: write, sent: map[ownKey][]byte{}}
	if replay != nil {
		w.prefix = *replay
		w.timers = replay.timers
	}
	if w.prefix.bytes != budget.bytes || w.prefix.records != budget.records {
		return nil, errValidatorHistoryProfile
	}
	return w, nil
}

func (w *validatorHistoryWriter) reference(c *validatorHistoryControl) {
	c.Anchor, c.Prefix, c.Records, c.Bytes = w.prefix.anchor, w.prefix.prefix, w.prefix.records, w.prefix.bytes
}

// abort never borrows unbounded space or a new ordinary reservation. Even a
// failed normal ledger permits at most one bounded terminal sync attempt.
// A physical sync failure is not a durability guarantee.
func (w *validatorHistoryWriter) abort(cause error) error {
	if cause == nil {
		cause = errValidatorHistoryProfile
	}
	if w.budget.failed == nil {
		w.budget.failed = cause
	}
	if w.terminal || w.prefix.anchor == (types.Hash{}) {
		return cause
	}
	w.terminal = true
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlHalt, HaltReason: validatorHaltFailure}
	if errors.Is(cause, errValidatorHistoryBudget) {
		c.HaltReason = validatorHaltLimit
	}
	w.reference(&c)
	record, err := encodeValidatorHistoryControl(walValidatorHalt, c)
	if err != nil {
		return fmt.Errorf("%w: terminal encoding: %v", cause, err)
	}
	n, err := validatorHistoryFrameBytes(record)
	if err != nil || n > validatorHistoryHaltBytes || w.prefix.records >= w.limits.Records || n > w.limits.Bytes-w.prefix.bytes {
		return fmt.Errorf("%w: terminal reserve unavailable", cause)
	}
	if _, err := w.write(record, true); err != nil {
		return fmt.Errorf("%w: terminal sync: %v", cause, err)
	}
	if err := w.prefix.advance(record); err != nil {
		return fmt.Errorf("%w: terminal prefix: %v", cause, err)
	}
	return cause
}

func (w *validatorHistoryWriter) appendReserved(record wal.Record, sync bool) (wal.Position, error) {
	if w.budget.active == nil {
		return wal.Position{}, w.abort(errValidatorHistoryProfile)
	}
	position, err := w.budget.active.appendRecord(record, func(rec wal.Record) (wal.Position, error) { return w.write(rec, sync) })
	if err != nil {
		return position, w.abort(err)
	}
	if err := w.prefix.advance(record); err != nil {
		return position, w.abort(err)
	}
	return position, nil
}

// append is the selected all-functional-writer seam. Only own/commit records
// belong to an executing Step. Admission/release is a separate atomic frame.
func (w *validatorHistoryWriter) append(record wal.Record, sync bool) (wal.Position, error) {
	if w.budget.failed != nil {
		return wal.Position{}, w.budget.failed
	}
	if w.step != nil {
		if record.Format != walFormat || record.Kind != walOwnMsg && record.Kind != walCommit {
			return wal.Position{}, w.abort(errValidatorHistoryProfile)
		}
		position, err := w.appendReserved(record, sync)
		if err != nil {
			return position, err
		}
		if record.Kind == walOwnMsg {
			own, err := decodeValidatorHistoryOwn(record)
			if err != nil {
				return position, w.abort(err)
			}
			w.step.own = append(w.step.own, own)
		} else {
			w.step.commits = append(w.step.commits, record)
		}
		w.step.effects = append(w.step.effects, record.Kind)
		return position, nil
	}
	if record.Format != nextHeightFormat || record.Kind != walDeferredAdmit && record.Kind != walDeferredDrop {
		return wal.Position{}, w.abort(errValidatorHistoryProfile)
	}
	n, err := validatorHistoryFrameBytes(record)
	if err != nil {
		return wal.Position{}, w.abort(err)
	}
	reservation, err := w.budget.reserve(n, 1)
	if err != nil {
		return wal.Position{}, w.abort(err)
	}
	position, err := w.appendReserved(record, true)
	if err == nil {
		err = reservation.finish()
	}
	if err != nil {
		return position, w.abort(err)
	}
	return position, nil
}

func (w *validatorHistoryWriter) control(kind uint8, c validatorHistoryControl) error {
	if w.step != nil {
		return w.abort(errValidatorHistoryProfile)
	}
	if c.Mode != validatorControlSeed {
		w.reference(&c)
	}
	record, err := encodeValidatorHistoryControl(kind, c)
	if err != nil {
		return w.abort(err)
	}
	n, err := validatorHistoryFrameBytes(record)
	if err != nil {
		return w.abort(err)
	}
	reservation, err := w.budget.reserve(n, 1)
	if err != nil {
		return w.abort(err)
	}
	if _, err := w.appendReserved(record, true); err != nil {
		return err
	}
	if c.Mode == validatorControlSeed {
		w.prefix.anchor, err = validatorHistoryRecordHash(record)
		if err != nil {
			return w.abort(err)
		}
	}
	if err := reservation.finish(); err != nil {
		return w.abort(err)
	}
	return nil
}

// Own sizes are checked before SignVote, including RLP growth, a 65-byte
// ECDSA signature and at most a 96-byte BLS seal of the supported signer.
func validatorHistoryOwnBound(b consensus.Broadcast) (uint64, error) {
	if b.Msg == nil {
		return 0, errValidatorHistoryProfile
	}
	msg := *b.Msg
	msg.Signature, msg.Seal = make([]byte, 65), make([]byte, 96)
	payload, err := codec.EncodeMessage(&msg)
	if err != nil {
		return 0, err
	}
	if err := transport.CheckOutbound(uint64(msg.Code), payload); err != nil {
		return 0, err
	}
	signed, err := validatorHistoryFrameBytes(encodeOwn(ownRec{Code: uint64(msg.Code), Payload: payload}))
	if err != nil {
		return 0, err
	}
	refused, err := validatorHistoryFrameBytes(encodeOwn(ownRec{Code: uint64(msg.Code), Refused: 1, Seq: msg.View.Sequence.Big(), Round: msg.View.Round.Big()}))
	return max(signed, refused), err
}

func validatorHistoryControlBound(kind uint8, c validatorHistoryControl) (uint64, error) {
	c.Records, c.Bytes = math.MaxInt64, math.MaxInt64
	record, err := encodeValidatorHistoryControl(kind, c)
	if err != nil {
		return 0, err
	}
	return validatorHistoryFrameBytes(record)
}

// begin reserves the entire Step before the first external output, then
// flushes original input/Env frames and a synchronous intent. The pure core
// result alone does not publish a snapshot or authorize an unreserved signer.
func (w *validatorHistoryWriter) begin(input inputRec, raw wal.Record, answers []envAnswer, outs []consensus.Output, c, footer validatorHistoryControl, kind uint8) error {
	if w.step != nil {
		return w.abort(errValidatorHistoryProfile)
	}
	c.Mode, c.InputRecord, c.InputKind = validatorControlIntent, w.prefix.records+1, input.Kind
	var err error
	c.InputHash, err = validatorHistoryInputHash(input.Kind, input.Body)
	if err != nil {
		return w.abort(err)
	}
	frames := []wal.Record{raw}
	for _, answer := range answers {
		witness, err := validatorHistoryWitness(answer.call)
		if err != nil {
			return w.abort(err)
		}
		c.Environment = append(c.Environment, witness)
		frames = append(frames, encodeEnv(witness.Bytes))
	}
	preview := w.prefix
	var size uint64
	for _, frame := range frames {
		n, err := validatorHistoryFrameBytes(frame)
		if err != nil {
			return w.abort(err)
		}
		size += n
		if err := preview.advance(frame); err != nil {
			return w.abort(err)
		}
	}
	c.Anchor, c.Prefix, c.Records, c.Bytes = preview.anchor, preview.prefix, preview.records, preview.bytes
	footer.Mode, footer.InputRecord, footer.InputKind, footer.InputHash = validatorControlComplete, c.InputRecord, c.InputKind, c.InputHash
	footer.Anchor, footer.Prefix = c.Anchor, c.Prefix
	count := uint64(len(frames)) + 2
	for _, out := range outs {
		switch o := out.(type) {
		case consensus.Broadcast:
			n, err := validatorHistoryOwnBound(o)
			if err != nil {
				return w.abort(err)
			}
			size += n
			count++
		case consensus.Commit:
			record, err := encodeCommit(o.Block, o.Round)
			if err != nil {
				return w.abort(err)
			}
			n, err := validatorHistoryFrameBytes(record)
			if err != nil {
				return w.abort(err)
			}
			size += n
			count++
		case consensus.Relay:
			if err := transport.CheckOutbound(uint64(o.Code), o.Payload); err != nil {
				return w.abort(err)
			}
		}
	}
	n, err := validatorHistoryControlBound(walValidatorIntent, c)
	if err != nil {
		return w.abort(err)
	}
	size += n
	n, err = validatorHistoryControlBound(kind, footer)
	if err != nil {
		return w.abort(err)
	}
	size += n
	if _, err := w.budget.reserve(size, count); err != nil {
		return w.abort(err)
	}
	for _, frame := range frames {
		if _, err := w.appendReserved(frame, false); err != nil {
			return err
		}
	}
	w.reference(&c)
	record, err := encodeValidatorHistoryControl(walValidatorIntent, c)
	if err != nil {
		return w.abort(err)
	}
	if _, err := w.appendReserved(record, true); err != nil {
		return err
	}
	w.step = &validatorHistoryStep{input: input, index: c.InputRecord, intent: &c, outs: outs}
	w.footer, w.footerKind = footer, kind
	return nil
}

func (w *validatorHistoryWriter) finish() error {
	s := w.step
	if s == nil || !validatorHistoryEffects(s.outs, s.effects) {
		return w.abort(errValidatorHistoryProfile)
	}
	if err := compareOwn(s.outs, s.own, map[ownKey][]byte{}); err != nil {
		return w.abort(err)
	}
	if _, err := validatorHistoryCompareCommits(s.outs, s.commits); err != nil {
		return w.abort(err)
	}
	w.reference(&w.footer)
	record, err := encodeValidatorHistoryControl(w.footerKind, w.footer)
	if err != nil {
		return w.abort(err)
	}
	if _, err := w.appendReserved(record, true); err != nil {
		return err
	}
	if err := w.budget.active.finish(); err != nil {
		return w.abort(err)
	}
	w.step = nil
	return nil
}
