package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

func loadTimerPolicy(path string) (*stepdriver.TimerPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	var out stepdriver.TimerPolicy
	if json.Unmarshal(raw, &out) != nil {
		return nil, stepdriver.ErrTimerPolicy
	}
	return &out, nil
}
func timedSource(source *stepdriver.TimedSource) any {
	if source == nil {
		return nil
	}
	return map[string]string{"writer_run": source.Writer, "engine_run": strconv.FormatUint(source.Engine, 10), "step": strconv.FormatUint(source.Step, 10), "ordinal": strconv.FormatUint(source.Ordinal, 10)}
}
func replayTimed(dir, chain string, policy stepdriver.TimerPolicy, yield func(stepdriver.TimedResult) error, complete func(stepdriver.TimedCompletion) error) error {
	raw, err := os.ReadFile(chain)
	if err != nil {
		return err
	}
	blocks, err := sim.DecodeChain(raw)
	if err != nil {
		return err
	}
	source, err := sim.NewChainSource(blocks)
	if err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		temp, err := os.MkdirTemp("", "wbft-timed-replay-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(temp)
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		manifest, err := journal.ReadBundle(f, fsys.OS{}, temp)
		_ = f.Close()
		if err != nil {
			return err
		}
		if !manifest.StartsAtRunStart {
			return stepdriver.ErrTraceNoSegment
		}
		dir = temp
	}
	answers, err := journal.OpenReader(fsys.OS{}, dir)
	if err != nil {
		return err
	}
	pool, err := stepdriver.NewAnswerPool(answers)
	if err != nil {
		return err
	}
	reader, err := journal.OpenReader(fsys.OS{}, dir)
	if err != nil {
		return err
	}
	return stepdriver.RunTimedTrace(reader, stepdriver.TimedOptions{Blocks: source, Answers: pool, Policy: policy, Complete: complete}, yield)
}
func timedRequest(req request, send func(any) error) error {
	if req.TimerPolicy == nil || req.TimerPolicy.RequestTimeoutSeconds == nil && req.TimerPolicy.MaxRequestTimeoutSeconds == nil || req.AnswerScope != "context" || req.Schedule != nil || req.OmitMissing || req.WarmupFrom != 0 || req.CompareFrom != 0 || req.FromStep != 0 || req.ToStep != 0 || req.WithVars {
		return send(map[string]any{"type": "error", "id": req.ID, "code": "timer_policy", "error": "timed replay requires a timer policy, context answers and complete recorded input"})
	}
	var count, sourceCount, generated, bad uint64
	var completions []stepdriver.TimedCompletion
	err := replayTimed(req.Journal, req.Chain, *req.TimerPolicy, func(result stepdriver.TimedResult) error {
		count++
		if result.Generated {
			generated++
		} else {
			sourceCount++
		}
		comparable := result.Source != nil && result.Suppression == ""
		if comparable && !result.Result.Match {
			bad++
		}
		applicationSources := []any{}
		for _, source := range result.ApplicationSources {
			copy := source.Source
			applicationSources = append(applicationSources, map[string]any{"source_input": timedSource(&copy), "output": strconv.FormatUint(source.Output, 10)})
		}
		var deadline any
		if result.Deadline != nil {
			deadline = strconv.FormatInt(int64(*result.Deadline), 10)
		}
		return send(map[string]any{
			"type": "timed_step", "id": req.ID, "execution_step": strconv.FormatUint(result.Execution, 10), "t_mono_ns": strconv.FormatInt(int64(result.Mono), 10),
			"source_input": timedSource(result.Source), "cause": timedSource(result.Cause), "signing_evidence": timedSource(result.Evidence), "parent_execution_step": strconv.FormatUint(result.ParentExecution, 10), "parent_output": strconv.FormatUint(result.ParentOutput, 10),
			"timer_arm": timedSource(result.Arm), "timer_arm_execution_step": strconv.FormatUint(result.ArmExecution, 10), "timer_deadline_mono_ns": deadline,
			"output_actions": result.Actions, "recorded_output_actions": result.RecordedActions, "execution_state": result.State, "generated": result.Generated, "suppression_reason": result.Suppression, "input": inputlog.Kind(result.Result.Input), "out_digest": "0x" + hex.EncodeToString(result.Result.OutDigest[:]),
			"match": result.Result.Match, "comparable": comparable, "outputs": len(result.Result.Outputs), "answer_sources": result.Result.AnswerSources, "application_question_sources": applicationSources, "counterfactual": result.Counterfactual, "execution_model": result.Model,
		})
	}, func(result stepdriver.TimedCompletion) error { completions = append(completions, result); return nil })
	if err != nil {
		code := "replay_error"
		switch {
		case errors.Is(err, stepdriver.ErrTraceSigningUnavailable):
			code = "signing_unavailable"
		case errors.Is(err, stepdriver.ErrTraceTiming):
			code = "timing_unavailable"
		case errors.Is(err, stepdriver.ErrTimerPolicy):
			code = "timer_policy"
		case errors.Is(err, stepdriver.ErrTraceEnvExhausted):
			code = "env_exhausted"
		case errors.Is(err, stepdriver.ErrTraceScheduleReservation):
			code = "reservation_unavailable"
		case errors.Is(err, stepdriver.ErrTraceAnswerLimit):
			code = "answer_limit"
		}
		reply := map[string]any{"type": "error", "id": req.ID, "code": code, "error": err.Error(), "counterfactual": true, "execution_model": stepdriver.TimedExperimentModel, "timer_policy": req.TimerPolicy, "steps": strconv.FormatUint(count, 10)}
		var failed *stepdriver.TimedError
		if errors.As(err, &failed) {
			reply["execution_step"] = strconv.FormatUint(failed.Execution, 10)
			reply["source_input"] = timedSource(failed.Source)
			reply["cause"] = timedSource(failed.Cause)
			reply["parent_execution_step"] = strconv.FormatUint(failed.ParentExecution, 10)
			reply["parent_output"] = strconv.FormatUint(failed.ParentOutput, 10)
		}
		return send(reply)
	}
	if count == 0 || len(completions) == 0 {
		return send(map[string]any{"type": "error", "id": req.ID, "code": "input_gap", "error": "no timed replay steps"})
	}
	scopes := []any{}
	for _, completion := range completions {
		if !completion.TimerTraceValidated {
			return send(map[string]any{"type": "error", "id": req.ID, "code": "timing_unavailable"})
		}
		scopes = append(scopes, map[string]any{"writer_run": completion.Writer, "engine_run": strconv.FormatUint(completion.Engine, 10), "execution_step": strconv.FormatUint(completion.Execution, 10), "horizon_mono_ns": strconv.FormatInt(int64(completion.Mono), 10), "pending_internal": completion.PendingInternal, "queued_timers": completion.QueuedTimers, "armed_timers": completion.ArmedTimers})
	}
	completion := completions[len(completions)-1]
	return send(map[string]any{"type": "timed_done", "id": req.ID, "steps": strconv.FormatUint(count, 10), "source_steps": strconv.FormatUint(sourceCount, 10), "generated_steps": strconv.FormatUint(generated, 10), "mismatches": strconv.FormatUint(bad, 10), "counterfactual": true, "execution_model": stepdriver.TimedExperimentModel, "timer_policy": req.TimerPolicy, "horizon": "recorded_source_end", "future_tail_generated": false, "timer_trace_validated": true, "scopes": scopes, "pending_internal": completion.PendingInternal, "queued_timers": completion.QueuedTimers, "armed_timers": completion.ArmedTimers, "horizon_mono_ns": strconv.FormatInt(int64(completion.Mono), 10)})
}
func replayTimedOnce(dir, chain string, policy *stepdriver.TimerPolicy, w io.Writer) int {
	failed := false
	enc := json.NewEncoder(w)
	err := timedRequest(request{ID: 1, TimerPolicy: policy, AnswerScope: "context", Journal: dir, Chain: chain}, func(value any) error {
		if result, ok := value.(map[string]any); ok && result["type"] == "error" {
			failed = true
		}
		return enc.Encode(value)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wbft-replay:", err)
		return 2
	}
	if failed {
		return 2
	}
	return 3
}
