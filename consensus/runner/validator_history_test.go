package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
)

// Budget tests use detached opaque frame bookkeeping. They do not edit a
// stored log, inject a storage error or execute signer/network/app effects.
func TestValidatorStartHistoryFrameAccounting(t *testing.T) {
	for _, size := range []int{0, 1, 55, 56, 255, 256, 1024} {
		record := wal.Record{Format: 5, Kind: 1, Body: bytes.Repeat([]byte{'m'}, size)}
		frame, err := wal.Encode(record)
		if err != nil {
			t.Fatal(err)
		}
		accounted, err := validatorHistoryFrameBytes(record)
		if err != nil || accounted != uint64(len(frame)) {
			t.Fatal("budget omitted functional frame overhead", size, accounted, len(frame), err)
		}
	}
	defaults, err := validatorHistoryLimits(nil)
	if err != nil || defaults.Bytes != 64<<20 || defaults.Records != 65536 {
		t.Fatal("supported defaults changed", defaults, err)
	}
	for _, invalid := range []ValidatorHistoryLimits{{}, {Bytes: 1}, {Records: 1}, {Bytes: math.MaxUint64, Records: 1}, {Bytes: 1, Records: math.MaxUint64}} {
		if _, err := validatorHistoryLimits(&invalid); err == nil {
			t.Fatal("invalid explicit history limits accepted", invalid)
		}
	}
}

func TestValidatorStartHistoryConfigurationIsExplicitAndFrozen(t *testing.T) {
	before := Config{}
	original, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if err := freezeValidatorHistoryConfig(&before, nil); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(before)
	if err != nil || !bytes.Equal(original, after) || before.ValidatorHistory != nil {
		t.Fatal("default configuration gained a profile", err)
	}
	explicit := ValidatorHistoryLimits{Bytes: 4096, Records: 40}
	wrong := Config{ValidatorHistory: &explicit}
	if freezeValidatorHistoryConfig(&wrong, nil) == nil {
		t.Fatal("limits silently selected a core behavior")
	}
	flags := consensus.ImprovementSet(0).With(consensus.DeferValidatorStart)
	cfg := Config{Core: consensus.Options{Improvements: flags}, ValidatorHistory: &explicit}
	if err := freezeValidatorHistoryConfig(&cfg, nil); err != nil {
		t.Fatal(err)
	}
	explicit.Bytes = 1
	if cfg.ValidatorHistory.Bytes != 4096 || cfg.ValidatorHistory == &explicit {
		t.Fatal("caller could mutate the frozen profile")
	}
	unknown := Config{Core: consensus.Options{Improvements: flags | 1<<63}}
	if freezeValidatorHistoryConfig(&unknown, nil) == nil {
		t.Fatal("unknown option entered the selected profile")
	}
	defaults := Config{Core: consensus.Options{Improvements: flags}}
	if err := freezeValidatorHistoryConfig(&defaults, nil); err != nil || *defaults.ValidatorHistory != DefaultValidatorHistoryLimits() {
		t.Fatal("live profile defaults are not frozen", err)
	}
	// Both logs are fresh owned in-memory stores; this only validates normal
	// configuration capabilities, without altering any stored record.
	for _, header := range []bool{false, true} {
		options := wal.Options{}
		if header {
			options.Header = func() []wal.Record { return nil }
		}
		log, _, err := wal.Open(fsys.NewMem(), "/history-config", options)
		if err != nil {
			t.Fatal(err)
		}
		for _, replay := range []bool{false, true} {
			cfg := Config{Core: consensus.Options{Improvements: flags}, ReplayWAL: replay}
			err := freezeValidatorHistoryConfig(&cfg, log)
			if (err == nil) != (replay && !header) {
				t.Fatal("unsupported durable profile was accepted", header, replay, err)
			}
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidatorStartHistoryRestoresCumulativeUsage(t *testing.T) {
	retained := []wal.Record{{Format: 5, Kind: 1, Body: []byte("seed")}, {Format: 1, Kind: 2, Body: []byte("input")}}
	var used uint64
	for _, record := range retained {
		n, err := validatorHistoryFrameBytes(record)
		if err != nil {
			t.Fatal(err)
		}
		used += n
	}
	limits := ValidatorHistoryLimits{Bytes: used, Records: uint64(len(retained))}
	budget, err := newValidatorHistoryBudget(limits, retained)
	if err != nil || budget.bytes != used || budget.records != 2 {
		t.Fatal("retained usage was reset", budget, err)
	}
	if _, err := budget.reserve(10, 1); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("restart bypassed an exhausted budget", err)
	}
	limits.Bytes--
	if _, err := newValidatorHistoryBudget(limits, retained); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("over-budget history accepted", err)
	}
	limits.Bytes, limits.Records = used, 1
	if _, err := newValidatorHistoryBudget(limits, retained); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("record limit ignored", err)
	}
}

func TestValidatorStartHistoryReservationPrecedesAppend(t *testing.T) {
	record := wal.Record{Format: 5, Kind: 1, Body: []byte("opaque bookkeeping")}
	n, err := validatorHistoryFrameBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := newValidatorHistoryBudget(ValidatorHistoryLimits{Bytes: 4 * n, Records: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := budget.reserve(2*n, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := budget.reserve(n, 1); err == nil {
		t.Fatal("concurrent owner reservation accepted")
	}
	writes := 0
	appendOriginal := func(wal.Record) (wal.Position, error) {
		writes++
		return wal.Position{Segment: 1, Offset: int64(writes)}, nil
	}
	if _, err := reservation.appendRecord(record, appendOriginal); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || budget.bytes != n || budget.records != 1 {
		t.Fatal("successful frame not accounted")
	}
	// The actual encoding may use less than the reserved worst-case capacity.
	if err := reservation.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := reservation.appendRecord(record, appendOriginal); err == nil || writes != 1 {
		t.Fatal("retired owner performed another append")
	}
	current, err := budget.reserve(2*n, 2)
	if err != nil {
		t.Fatal("unused worst-case capacity was not released", err)
	}
	for range 2 {
		if _, err := current.appendRecord(record, appendOriginal); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := current.appendRecord(record, appendOriginal); !errors.Is(err, errValidatorHistoryBudget) || writes != 3 {
		t.Fatal("writer ran beyond the reserved step", writes, err)
	}
	if err := current.finish(); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("failed step was allowed to finish", err)
	}
	if _, err := budget.reserve(n, 1); !errors.Is(err, errValidatorHistoryBudget) || writes != 3 {
		t.Fatal("a failed step resumed through a smaller reservation", writes, err)
	}
}

func TestValidatorStartHistoryRejectsUnderestimatedAndInvalidReservations(t *testing.T) {
	budget, err := newValidatorHistoryBudget(ValidatorHistoryLimits{Bytes: 128, Records: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][2]uint64{{0, 1}, {10, 0}, {9, 1}, {128, math.MaxUint64}} {
		if _, err := budget.reserve(invalid[0], invalid[1]); err == nil {
			t.Fatal("invalid reservation accepted", invalid)
		}
	}
	r, err := budget.reserve(10, 1)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	_, err = r.appendRecord(wal.Record{Body: []byte("larger than the reservation")}, func(wal.Record) (wal.Position, error) { writes++; return wal.Position{}, nil })
	if !errors.Is(err, errValidatorHistoryBudget) || writes != 0 || budget.bytes != 0 || budget.records != 0 {
		t.Fatal("underestimated encoding reached the writer", writes, err)
	}
	if err := r.finish(); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("underestimated step acquired a completion", err)
	}
	if _, err := budget.reserve(10, 1); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("underestimated step resumed with a smaller reservation", err)
	}
}

func TestValidatorStartHistoryCapacityFailureCannotResumeSmallerStep(t *testing.T) {
	budget, err := newValidatorHistoryBudget(ValidatorHistoryLimits{Bytes: 30, Records: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := budget.reserve(40, 4); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("oversized whole-step reservation accepted", err)
	}
	if _, err := budget.reserve(10, 1); !errors.Is(err, errValidatorHistoryBudget) || budget.bytes != 0 || budget.records != 0 {
		t.Fatal("failed step resumed with a smaller reservation", err)
	}
}
