package stepdriver_test

import (
	"context"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestSourceContextReplayRetainsEveryOriginalApplicationAnswer(t *testing.T) {
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-context-answers", Seed: 5, Validators: keys(4), Until: sim.Stop{Height: 8, Duration: time.Minute}}, sim.Output{})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	sources := 0
	for _, files := range result.Journals {
		fs, dir := memJournal(t, files)
		answers, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		pool, err := stepdriver.NewAnswerPool(answers)
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := journal.OpenReader(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		var want []stepdriver.StepResult
		if err = stepdriver.RunTrace(baseline, stepdriver.TraceOptions{Blocks: blocks}, func(s stepdriver.StepResult) error { want = append(want, s); return nil }); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			reader, err := journal.OpenReader(fs, dir)
			if err != nil {
				t.Fatal(err)
			}
			i := 0
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks, AnswerScope: "context", Answers: pool}, func(s stepdriver.StepResult) error {
				if i >= len(want) || !s.Match || !s.ContextAnswers || s.OutDigest != want[i].OutDigest || len(s.EnvCalls) != len(want[i].EnvCalls) {
					t.Fatal("context replay changed original output", s.EngineRun, s.Step)
				}
				for _, source := range s.AnswerSources {
					sources++
					if source.WriterRun != s.WriterRun || source.EngineRun != s.EngineRun || source.Step != s.Step || source.Call < 1 {
						t.Fatal("original response borrowed another source", source, s.WriterRun, s.EngineRun, s.Step)
					}
				}
				i++
				return nil
			})
			if err != nil || i != len(want) {
				t.Fatal(err, i, len(want))
			}
		}
	}
	if sources == 0 {
		t.Fatal("application responses were not exercised")
	}
}
