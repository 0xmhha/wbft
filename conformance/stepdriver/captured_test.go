package stepdriver_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestCapturedMessageDeletionRunsActualOmission(t *testing.T) {
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "captured-deletion", Seed: 11, Validators: keys(4), Until: sim.Stop{Height: 3, Duration: time.Minute}}, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(result, err)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		records, err := journal.ReadAll(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		var target *journal.StepRec
		var token uint64
		var writerRun string
		for _, rec := range records {
			if seg, ok := rec.Body.(*journal.SegmentRec); ok {
				writerRun = seg.Run
			}
			if step, ok := rec.Body.(*journal.StepRec); ok && step.InputKind == inputlog.KindCapturedMessage {
				target = step
				token, err = inputlog.CapturedReference(step.Input)
				if err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		if target == nil {
			continue
		}
		reader, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		capture, err := reader.ResolveCapture(writerRun, token)
		if err != nil || capture.Record.Capture != token {
			t.Fatal(capture, err)
		}
		baseline := 0
		if err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(s stepdriver.StepResult) error {
			baseline++
			if !s.Match {
				t.Error(s)
			}
			return nil
		}); err != nil || baseline == 0 {
			t.Fatal(baseline, err)
		}
		changed := fsys.NewMem()
		out := "/changed"
		identity := records[0].Body.(*journal.SegmentRec).Identity
		writer, err := journal.Open(journal.Options{FS: changed, Dir: out, Synchronous: true}, identity)
		if err != nil {
			t.Fatal(err)
		}
		deleted := 0
		for _, rec := range records[1:] {
			if m, ok := rec.Body.(*journal.MsgRec); ok && m.Dir == journal.In && m.Capture == token {
				deleted++
				continue
			}
			writer.Put(rec)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		if deleted != 1 {
			t.Fatal(deleted)
		}
		// Closed reproduction never recovers the omitted frame from inline bytes.
		r, err := journal.OpenReader(changed, out)
		if err != nil {
			t.Fatal(err)
		}
		err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: blocks}, func(stepdriver.StepResult) error { return nil })
		if !errors.Is(err, stepdriver.ErrTraceMissingInput) {
			t.Fatal("deleted source falsely reproduced", err)
		}
		// The explicit loss experiment feeds no input at that recorded position.
		r, err = journal.OpenReader(changed, out)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		err = stepdriver.RunTrace(r, stepdriver.TraceOptions{Blocks: blocks, OmitMissingCaptured: true}, func(s stepdriver.StepResult) error {
			if s.EngineRun == target.EngineRun && s.Step == target.Step {
				found = true
				if !s.Omitted || s.Input != nil || len(s.Outputs) != 0 || s.Match || s.RecordedInputKind != inputlog.KindCapturedMessage {
					t.Fatalf("not an actual omitted input: %+v", s)
				}
				expected, e := inputlog.OutDigest([]consensus.Output{})
				if e != nil || s.OutDigest != expected {
					t.Fatal(s.OutDigest, expected, e)
				}
				return io.EOF // first changed position is sufficient for this assertion
			}
			if !s.Match {
				t.Fatal("difference before deleted message", s.Step)
			}
			return nil
		})
		if !found || !errors.Is(err, io.EOF) {
			t.Fatal(found, err)
		}
		return
	}
	t.Fatal("no captured peer input")
}
