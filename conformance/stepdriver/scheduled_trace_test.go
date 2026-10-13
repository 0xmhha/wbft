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

func TestScheduledTraceExecutesDropAndDelayWithOriginalCoordinates(t *testing.T) {
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-input-schedule", Seed: 11, Validators: keys(4), Until: sim.Stop{Height: 5, Duration: time.Minute}}, sim.Output{})
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
		writer := ""
		var target *journal.StepRec
		var next uint64
		for _, rec := range records {
			if seg, ok := rec.Body.(*journal.SegmentRec); ok {
				writer = seg.Run
			}
			if b, ok := rec.Body.(*journal.StepRec); ok {
				if target == nil && b.InputKind == inputlog.KindCapturedMessage {
					target = b
				} else if target != nil && b.EngineRun == target.EngineRun && b.Step > target.Step {
					next = b.Step
					break
				}
			}
		}
		if target == nil || next == 0 {
			continue
		}
		poolReader, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		pool, err := stepdriver.NewAnswerPool(poolReader)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range []string{"drop", "delay"} {
			reader, err := journal.OpenReader(fs, dir)
			if err != nil {
				t.Fatal(err)
			}
			spec := &stepdriver.TraceSchedule{Action: action, WriterRun: writer, EngineRun: target.EngineRun, Step: target.Step}
			if action == "delay" {
				spec.OtherStep = next
			}
			found := false
			execution := uint64(0)
			missingReservation := false
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks, AnswerScope: "context", Answers: pool, Schedule: spec}, func(s stepdriver.StepResult) error {
				if s.Scheduled == nil || s.Scheduled.Step != s.Step || s.Scheduled.EngineRun != s.EngineRun || s.Scheduled.WriterRun != s.WriterRun || s.Scheduled.ExecutionStep != execution+1 || s.Scheduled.JSeq == 0 {
					t.Fatal("lost source/execution coordinates", s)
				}
				execution = s.Scheduled.ExecutionStep
				if s.Step == target.Step {
					found = true
					if action == "drop" && (!s.Omitted || s.SuppressionReason != "requested_drop" || s.Input != nil || len(s.Outputs) != 0) {
						t.Fatal("drop fed the recorded input", s)
					}
					if action == "delay" && (s.Omitted || s.Scheduled.ExecutionStep != next) {
						t.Fatal("delay did not move input", s)
					}
					if action == "delay" {
						return io.EOF
					}
				}
				if action == "drop" && s.SuppressionReason == "reservation_unavailable" {
					missingReservation = true
					if !s.Omitted || s.Input != nil || len(s.Outputs) != 0 {
						t.Fatal("unproduced internal input was fed", s)
					}
				}
				if action == "drop" && !found && !s.Match {
					t.Fatal("difference before requested change", s)
				}
				return nil
			})
			if !found || action == "delay" && !errors.Is(err, io.EOF) || action == "drop" && (err != nil || !missingReservation) {
				t.Fatal(action, found, missingReservation, err)
			}
		}
		return
	}
	t.Fatal("no captured input")
}
