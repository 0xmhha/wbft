package runner

import (
	"errors"
	"fmt"
	"math"

	"github.com/0xmhha/wbft/consensus/wal"
)

const (
	defaultValidatorHistoryBytes   uint64 = 64 << 20
	defaultValidatorHistoryRecords uint64 = 65536
	validatorHistoryFrameOverhead  uint64 = 10
)

// ValidatorHistoryLimits bounds retained functional frames of an explicitly
// selected validator-start profile. It is not a heap, CPU or whole-disk cap.
// Reaching either bound halts progress while preserving the original history.
type ValidatorHistoryLimits struct {
	Bytes   uint64 `json:"bytes,string"`
	Records uint64 `json:"records,string"`
}

// DefaultValidatorHistoryLimits returns the finite experimental history cap.
// Normal progress also consumes it; it is not an uptime recommendation.
func DefaultValidatorHistoryLimits() ValidatorHistoryLimits {
	return ValidatorHistoryLimits{Bytes: defaultValidatorHistoryBytes, Records: defaultValidatorHistoryRecords}
}

// Validate checks explicit limits without changing them or selecting a profile.
func (limits ValidatorHistoryLimits) Validate() error {
	_, err := validatorHistoryLimits(&limits)
	return err
}

func validatorHistoryLimits(selected *ValidatorHistoryLimits) (ValidatorHistoryLimits, error) {
	limits := DefaultValidatorHistoryLimits()
	if selected != nil {
		limits = *selected
	}
	if limits.Bytes == 0 || limits.Records == 0 || limits.Bytes > math.MaxInt64 || limits.Records > math.MaxInt64 {
		return ValidatorHistoryLimits{}, fmt.Errorf("runner: validator-start history requires positive representable byte and record limits")
	}
	return limits, nil
}

var errValidatorHistoryBudget = errors.New("runner: validator-start history limit exhausted")

// validatorHistoryBudget is owned by the core actor. Only one step or control
// reservation can be active. Restart reconstructs usage from original frames.
type validatorHistoryBudget struct {
	limits         ValidatorHistoryLimits
	bytes, records uint64
	active         *validatorHistoryReservation
	failed         error
}

type validatorHistoryReservation struct {
	owner          *validatorHistoryBudget
	bytes, records uint64
	closed         bool
}

func validatorHistoryFrameBytes(record wal.Record) (uint64, error) {
	if len(record.Body) > wal.MaxRecordBytes {
		return 0, wal.ErrTooLarge
	}
	// The functional WAL frame is length+CRC (8), format+kind (2), body.
	return uint64(len(record.Body)) + validatorHistoryFrameOverhead, nil
}

func newValidatorHistoryBudget(limits ValidatorHistoryLimits, retained []wal.Record) (*validatorHistoryBudget, error) {
	checked, err := validatorHistoryLimits(&limits)
	if err != nil {
		return nil, err
	}
	budget := &validatorHistoryBudget{limits: checked}
	for _, record := range retained {
		n, err := validatorHistoryFrameBytes(record)
		if err != nil {
			return nil, err
		}
		if budget.records == checked.Records || n > checked.Bytes-budget.bytes {
			return nil, errValidatorHistoryBudget
		}
		budget.bytes += n
		budget.records++
	}
	return budget, nil
}

// reserve must run before any external output of the step. Sizes include
// the worst supported own/refusal encoding and its eventual completion frame.
func (budget *validatorHistoryBudget) reserve(bytes, records uint64) (*validatorHistoryReservation, error) {
	if budget.failed != nil {
		return nil, budget.failed
	}
	if budget.active != nil || records == 0 || bytes == 0 || records > math.MaxUint64/validatorHistoryFrameOverhead || bytes < records*validatorHistoryFrameOverhead {
		return nil, fmt.Errorf("runner: invalid validator-start history reservation")
	}
	if records > budget.limits.Records-budget.records || bytes > budget.limits.Bytes-budget.bytes {
		budget.failed = errValidatorHistoryBudget
		return nil, errValidatorHistoryBudget
	}
	r := &validatorHistoryReservation{owner: budget, bytes: bytes, records: records}
	budget.active = r
	return r, nil
}

// appendRecord checks the reservation before invoking the original WAL writer.
// A writer error latches the budget; it never permits another step to proceed.
func (r *validatorHistoryReservation) appendRecord(record wal.Record, appendOriginal func(wal.Record) (wal.Position, error)) (wal.Position, error) {
	if r.closed || r.owner.active != r || appendOriginal == nil {
		return wal.Position{}, fmt.Errorf("runner: inactive validator-start history reservation")
	}
	if r.owner.failed != nil {
		return wal.Position{}, r.owner.failed
	}
	n, err := validatorHistoryFrameBytes(record)
	if err != nil {
		return wal.Position{}, err
	}
	if r.records == 0 || n > r.bytes {
		r.owner.failed = errValidatorHistoryBudget
		return wal.Position{}, errValidatorHistoryBudget
	}
	position, err := appendOriginal(record)
	if err != nil {
		r.owner.failed = err
		return position, err
	}
	r.records--
	r.bytes -= n
	r.owner.records++
	r.owner.bytes += n
	return position, nil
}

// finish releases unused worst-case capacity only after the caller durably
// completed the step. Verifying the completion control belongs to the profile.
func (r *validatorHistoryReservation) finish() error {
	if r.closed || r.owner.active != r {
		return fmt.Errorf("runner: inactive validator-start history reservation")
	}
	if r.owner.failed != nil {
		return r.owner.failed
	}
	r.closed = true
	r.owner.active = nil
	return nil
}
