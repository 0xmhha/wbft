package stepdriver_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestLiveTimerRecordsJoinExactCoreOutputAndDequeuedInput(t *testing.T) {
	validators := keys(4)
	for i := range validators {
		v, err := sim.NewValidator(validators[i].ECDSA)
		if err != nil {
			t.Fatal(err)
		}
		validators[i] = v
	}
	var links []sim.Link
	for i, a := range validators {
		for j, b := range validators {
			if i != j {
				links = append(links, sim.Link{From: a.Address(), To: b.Address(), Delay: []time.Duration{3 * time.Second}})
			}
		}
	}
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "timer-operation-evidence", Seed: 19, Validators: validators, Links: links, Until: sim.Stop{Height: 2, Duration: time.Minute}}, sim.Output{JournalDir: t.TempDir()})
	if err != nil || len(result.Journals) != 4 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	checked, queued, popped := 0, 0, 0
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		records, err := journal.ReadAll(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		type point struct{ engine, step uint64 }
		steps := map[point]*journal.StepRec{}
		outputs := map[point][]consensus.Output{}
		for _, r := range records {
			if s, ok := r.Body.(*journal.StepRec); ok {
				steps[point{s.EngineRun, s.Step}] = s
			}
			if s, ok := r.Body.(*journal.SegmentRec); ok && s.Core.TimerTrace != journal.TimerTraceVersion {
				t.Fatal("trace not declared", s)
			}
		}
		reader, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(s stepdriver.StepResult) error {
			if !s.Match {
				t.Fatal("recorded core output changed", s)
			}
			outputs[point{s.EngineRun, s.Step}] = s.Outputs
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var sequence uint64
		var mono time.Duration
		for _, r := range records {
			trace, ok := r.Body.(*journal.TimerRec)
			if !ok {
				continue
			}
			if trace.Sequence != sequence+1 || trace.Mono < mono {
				t.Fatal("timer operation order broken", trace, sequence, mono)
			}
			sequence = trace.Sequence
			mono = trace.Mono
			checked++
			if trace.Action == "arm" && trace.Source == "core" {
				source := point{trace.EngineRun, trace.Step}
				out := outputs[source]
				if trace.Output == 0 || trace.Output > uint64(len(out)) {
					t.Fatal("output coordinate unavailable", trace)
				}
				arm, ok := out[trace.Output-1].(consensus.ArmTimer)
				if !ok {
					t.Fatal("timer cause is not arm", trace)
				}
				raw, err := inputlog.Encode(consensus.Timeout{Kind: arm.Kind, View: arm.View, Round: arm.Round, Gen: arm.Gen, Msg: arm.Msg})
				if err != nil {
					t.Fatal(err)
				}
				step := steps[source]
				if !bytes.Equal(raw, trace.Input) || step.Entry == nil || trace.EntryMono != step.Entry.Mono || trace.Deadline != step.Entry.Mono+arm.Duration || trace.Mono < step.Entry.Mono || trace.Mono > step.Mono {
					t.Fatal("arm evidence differs from actual core output", trace, step)
				}
			}
			if trace.Action == "queued" {
				queued++
				if trace.Mono < trace.Deadline || trace.EngineRun != trace.ArmEngineRun || trace.Step != trace.ArmStep || trace.Output != trace.ArmOutput {
					t.Fatal("queue evidence lost arm cause", trace)
				}
			}
			if trace.Action == "pop" {
				popped++
				step := steps[point{trace.EngineRun, trace.Step}]
				if step == nil || step.InputKind != inputlog.KindTimeout || !bytes.Equal(step.Input, trace.Input) || trace.Mono > step.Entry.Mono {
					t.Fatal("dequeued input does not match source step", trace, step)
				}
			}
		}
	}
	if checked == 0 || queued == 0 || popped == 0 {
		t.Fatal("live operation coverage absent", checked, queued, popped)
	}
}
