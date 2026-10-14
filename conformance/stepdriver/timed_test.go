package stepdriver_test

import (
	"context"
	"errors"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"testing"
	"time"
)

func TestTimedTraceRegeneratesRecordedBaselineAndChangedExpiry(t *testing.T) {
	validators := keys(4)
	for i := range validators {
		v, e := sim.NewValidator(validators[i].ECDSA)
		if e != nil {
			t.Fatal(e)
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
	result, e := sim.Run(context.Background(), sim.Scenario{Name: "timed-inputs", Seed: 19, Validators: validators, Links: links, Until: sim.Stop{Height: 2, Duration: time.Minute}}, sim.Output{JournalDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Journals) != 4 {
		t.Fatal("missing source journals", len(result.Journals), result.Violations)
	}
	blocks, e := sim.NewChainSource(result.Chain)
	if e != nil {
		t.Fatal(e)
	}
	baselineTimers, generated, regenerated := 0, 0, 0
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		poolReader, e := journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		pool, e := stepdriver.NewAnswerPool(poolReader)
		if e != nil {
			t.Fatal(e)
		}
		reader, e := journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		e = stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: blocks, Answers: pool}, func(r stepdriver.TimedResult) error {
			if r.Source == nil || !r.Result.Match {
				t.Fatal("baseline source or output lost", r)
			}
			if _, ok := r.Result.Input.(consensus.Timeout); ok {
				baselineTimers++
				if r.Arm == nil {
					t.Fatal("timer arm source lost")
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal("baseline", e)
		}
		changed := uint64(1)
		reader, e = journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		e = stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: blocks, Answers: pool, Policy: stepdriver.TimerPolicy{RequestTimeoutSeconds: &changed}}, func(r stepdriver.TimedResult) error {
			if !r.Counterfactual || r.Model != stepdriver.TimedExperimentModel {
				t.Fatal("experiment model lost", r)
			}
			if r.Generated {
				if _, ok := r.Result.Input.(consensus.Timeout); ok {
					generated++
					if r.Arm == nil {
						t.Fatal("timer arm missing")
					}
				}
				if _, ok := r.Result.Input.(consensus.Timeout); !ok {
					regenerated++
					if r.Cause == nil || r.ParentExecution == 0 {
						t.Fatal("internal causal reservation lost", r)
					}
				}
				if r.Source != nil || r.Result.Step != 0 {
					t.Fatal("generated timer acquired a fictitious source", r)
				}
			}
			return nil
		})
		if e != nil {
			if !errors.Is(e, stepdriver.ErrTraceEnvExhausted) && !errors.Is(e, stepdriver.ErrTraceSigningUnavailable) {
				t.Fatal("changed policy", e)
			}
			var failed *stepdriver.TimedError
			if !errors.As(e, &failed) || failed.Execution == 0 {
				t.Fatal("execution failure coordinates missing", e)
			}
			if errors.Is(e, stepdriver.ErrTraceSigningUnavailable) && (failed.Source != nil || failed.Cause == nil || failed.ParentExecution == 0) {
				t.Fatal("generated signing failure provenance missing", failed)
			}
		}
	}
	if baselineTimers == 0 || generated == 0 || regenerated == 0 {
		t.Fatal("expiry execution not covered", baselineTimers, generated, regenerated)
	}
}

type missingEntryReader struct{ source stepdriver.JournalReader }

func (r missingEntryReader) Next() (journal.Record, error) {
	rec, e := r.source.Next()
	if b, ok := rec.Body.(*journal.StepRec); ok {
		copy := *b
		copy.Entry = nil
		rec.Body = &copy
	}
	return rec, e
}
func TestTimedTraceRefusesUnknownEntryBeforeExecution(t *testing.T) {
	result, e := sim.Run(context.Background(), sim.Scenario{Name: "timed-unknown-entry", Seed: 3, Validators: keys(4), Until: sim.Stop{Height: 3, Duration: time.Minute}}, sim.Output{JournalDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	blocks, e := sim.NewChainSource(result.Chain)
	if e != nil {
		t.Fatal(e)
	}
	checked := 0
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		r, e := journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		pool, e := stepdriver.NewAnswerPool(r)
		if e != nil {
			t.Fatal(e)
		}
		r, e = journal.OpenReader(fs, dir)
		if e != nil {
			t.Fatal(e)
		}
		yielded := 0
		e = stepdriver.RunTimedTrace(missingEntryReader{r}, stepdriver.TimedOptions{Blocks: blocks, Answers: pool}, func(stepdriver.TimedResult) error { yielded++; return nil })
		if !errors.Is(e, stepdriver.ErrTraceTiming) || yielded != 0 {
			t.Fatal("unknown entry executed", e, yielded)
		}
		checked++
	}
	if checked != 4 {
		t.Fatal("source coverage", checked)
	}
}
