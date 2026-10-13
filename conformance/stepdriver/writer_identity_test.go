package stepdriver_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/observe/journal"
)

type writerSequence struct {
	readers []*journal.Reader
	current int
}

func (r *writerSequence) Next() (journal.Record, error) {
	for r.current < len(r.readers) {
		record, err := r.readers[r.current].Next()
		if err == io.EOF {
			r.current++
			continue
		}

		return record, err
	}
	return journal.Record{}, io.EOF
}
func (r *writerSequence) ResolveCapture(run string, id uint64) (journal.CapturedFrame, error) {
	for _, reader := range r.readers {
		frame, err := reader.ResolveCapture(run, id)
		if !errors.Is(err, journal.ErrCaptureMissing) {
			return frame, err
		}
	}
	return journal.CapturedFrame{}, journal.ErrCaptureMissing
}
func TestReplayUsesEachWriterOptions(t *testing.T) {
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-writer-options", Seed: 5, Validators: keys(4), Until: sim.Stop{Height: 3, Duration: time.Minute}}, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	sequence := &writerSequence{}
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		reader, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		sequence.readers = append(sequence.readers, reader)
	}
	if len(sequence.readers) != 4 {
		t.Fatal(len(sequence.readers))
	}
	counts := map[string]int{}
	err = stepdriver.RunTrace(sequence, stepdriver.TraceOptions{Blocks: blocks}, func(s stepdriver.StepResult) error {
		if !s.Match || s.WriterRun == "" {
			t.Fatal("writer identity or options did not reproduce", s.WriterRun, s.EngineRun, s.Step, s.Match)
		}
		counts[s.WriterRun]++
		return nil
	})
	if err != nil || len(counts) != 4 {
		t.Fatal(err, counts)
	}
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		reader, e := journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		e = stepdriver.RunTrace(reader, stepdriver.TraceOptions{}, func(stepdriver.StepResult) error { t.Fatal("a failed step was emitted as a comparison"); return nil })
		var failed *stepdriver.TraceError
		if !errors.As(e, &failed) || failed.WriterRun == "" || failed.EngineRun == 0 || failed.Step != 1 || failed.Err == nil {
			t.Fatal("failed source identity missing", e)
		}
		break
	}

}
