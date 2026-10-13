package stepdriver_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

type warmupReader struct {
	base      *journal.Reader
	omitStart bool
	gap       bool
}

func (r *warmupReader) Next() (journal.Record, error) {
	for {
		v, err := r.base.Next()
		if err != nil {
			return v, err
		}
		if s, ok := v.Body.(*journal.StepRec); ok {
			if r.omitStart && s.InputKind == inputlog.KindStart {
				continue
			}
			if r.gap {
				r.gap = false
				return journal.Record{Kind: journal.KindGap, Body: &journal.GapRec{Dropped: 1}}, nil
			}
		}
		return v, nil
	}
}
func (r *warmupReader) ResolveCapture(run string, id uint64) (journal.CapturedFrame, error) {
	return r.base.ResolveCapture(run, id)
}

func warmupFixture(t *testing.T) (func(bool, bool) *warmupReader, stepdriver.BlockSource) {
	t.Helper()
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-bounded-warmup", Seed: 5, Validators: keys(4), Until: sim.Stop{Height: 5, Duration: time.Minute}}, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		open := func(omit, gap bool) *warmupReader {
			t.Helper()
			r, e := journal.OpenReader(fs, dir)
			if e != nil {
				t.Fatal(e)
			}
			return &warmupReader{base: r, omitStart: omit, gap: gap}
		}
		return open, blocks
	}
	t.Fatal("no generated journal")
	return nil, nil
}

func TestBoundedWarmupIsExplicitAndNeverARecordedStart(t *testing.T) {
	open, blocks := warmupFixture(t)
	count := 0
	if err := stepdriver.RunTrace(open(true, false), stepdriver.TraceOptions{Blocks: blocks}, func(stepdriver.StepResult) error { count++; return nil }); err != nil || count != 0 {
		t.Fatal("closed replay synthesised a missing start", err, count)
	}
	approximate, warming, selected := 0, 0, 0
	err := stepdriver.RunTrace(open(true, false), stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 1, CompareFromHeight: 3}}, func(s stepdriver.StepResult) error {
		if s.RecordedInputKind == inputlog.KindStart || !s.Approximate || s.WriterRun == "" || s.Step <= 1 {
			t.Fatal("synthetic start or approximation label missing", s)
		}
		approximate++
		if s.Warmup {
			warming++
		} else {
			selected++
		}
		return nil
	})
	if err != nil || approximate == 0 || warming == 0 || selected == 0 {
		t.Fatal(err, approximate, warming, selected)
	}
	// An available recorded start uses the normal exact path even with fallback configured.
	err = stepdriver.RunTrace(open(false, false), stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 1, CompareFromHeight: 3}}, func(s stepdriver.StepResult) error {
		if s.Approximate || s.Warmup || !s.Match {
			t.Fatal("exact replay changed", s)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoundedWarmupRefusesLossAndInvalidBounds(t *testing.T) {
	open, blocks := warmupFixture(t)
	opts := stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 1, CompareFromHeight: 3}}
	if err := stepdriver.RunTrace(open(true, true), opts, func(stepdriver.StepResult) error { t.Fatal("gap emitted as replay"); return nil }); !errors.Is(err, stepdriver.ErrTraceGap) {
		t.Fatal("loss accepted", err)
	}
	for _, w := range []stepdriver.TraceWarmup{{}, {FromHeight: 1, CompareFromHeight: 1}, {FromHeight: 2, CompareFromHeight: 1}, {FromHeight: 1, CompareFromHeight: 10002}} {
		opts.Warmup = &w
		if err := stepdriver.RunTrace(open(true, false), opts, func(stepdriver.StepResult) error { t.Fatal("invalid bounds replayed"); return nil }); !errors.Is(err, stepdriver.ErrTraceWarmupUnavailable) {
			t.Fatal(w, err)
		}
	}
}

func TestBoundedWarmupPrunedHeightWindowAndMissingHead(t *testing.T) {
	open, blocks := warmupFixture(t)
	counts := [2]int{}
	opts := stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 2, CompareFromHeight: 4}}
	err := stepdriver.RunTrace(open(true, false), opts, func(s stepdriver.StepResult) error {
		if !s.Approximate {
			t.Fatal("missing approximate marker", s)
		}
		if s.Warmup {
			counts[0]++
		} else {
			counts[1]++
		}
		return nil
	})
	if err != nil || counts[0] == 0 || counts[1] == 0 {
		t.Fatal(err, counts)
	}
	opts.Blocks = nil
	err = stepdriver.RunTrace(open(true, false), opts, func(stepdriver.StepResult) error { t.Fatal("unavailable head replayed"); return nil })
	var failed *stepdriver.TraceError
	if !errors.Is(err, stepdriver.ErrTraceWarmupUnavailable) || !errors.As(err, &failed) || failed.WriterRun == "" || failed.Step == 0 {
		t.Fatal("missing source failure identity", err)
	}
}

// The first missing start is approximate; a later recorded start removes that status.
type firstStartMissing struct {
	*journal.Reader
	skipped bool
}

func (r *firstStartMissing) Next() (journal.Record, error) {
	for {
		v, err := r.Reader.Next()
		if err != nil {
			return v, err
		}
		if s, ok := v.Body.(*journal.StepRec); ok && s.InputKind == inputlog.KindStart && !r.skipped {
			r.skipped = true
			continue
		}
		return v, nil
	}
}

type startSequence struct {
	readers   []stepdriver.JournalReader
	originals []*journal.Reader
	current   int
}

func (r *startSequence) Next() (journal.Record, error) {
	for r.current < len(r.readers) {
		v, e := r.readers[r.current].Next()
		if e == io.EOF {
			r.current++
			continue
		}
		return v, e
	}
	return journal.Record{}, io.EOF
}
func (r *startSequence) ResolveCapture(run string, id uint64) (journal.CapturedFrame, error) {
	for _, reader := range r.originals {
		f, e := reader.ResolveCapture(run, id)
		if !errors.Is(e, journal.ErrCaptureMissing) {
			return f, e
		}
	}
	return journal.CapturedFrame{}, journal.ErrCaptureMissing
}
func TestRecordedStartEndsApproximateState(t *testing.T) {
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-warmup-writer-reset", Seed: 3, Validators: keys(4), Until: sim.Stop{Height: 4, Duration: time.Minute}}, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	sequence := &startSequence{}
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		reader, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		sequence.originals = append(sequence.originals, reader)
		if len(sequence.readers) == 0 {
			sequence.readers = append(sequence.readers, &firstStartMissing{Reader: reader})
		} else {
			sequence.readers = append(sequence.readers, reader)
		}
	}
	approximate, exact := 0, 0
	err = stepdriver.RunTrace(sequence, stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 1, CompareFromHeight: 3}}, func(s stepdriver.StepResult) error {
		if s.Approximate {
			approximate++
		} else {
			exact++
			if !s.Match {
				t.Fatal("recorded writer start diverged", s)
			}
		}
		return nil
	})
	if err != nil || approximate == 0 || exact == 0 {
		t.Fatal(err, approximate, exact)
	}
}

func TestBoundedWarmupPastAvailablePrefixIsUnavailable(t *testing.T) {
	open, blocks := warmupFixture(t)
	err := stepdriver.RunTrace(open(true, false), stepdriver.TraceOptions{Blocks: blocks, Warmup: &stepdriver.TraceWarmup{FromHeight: 100, CompareFromHeight: 102}}, func(stepdriver.StepResult) error { t.Fatal("unavailable prefix emitted"); return nil })
	if !errors.Is(err, stepdriver.ErrTraceWarmupUnavailable) {
		t.Fatal("empty approximate replay accepted", err)
	}
}
