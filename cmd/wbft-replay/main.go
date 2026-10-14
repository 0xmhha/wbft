// Command wbft-replay replays a recorded message journal through the
// consensus core and reports, step by step, whether the replayed outputs
// match the recorded ones. It wraps conformance/stepdriver.RunTrace.
//
// With -journal it replays one journal directory, or a journal bundle
// written by wbft-journal export that starts at the start of a writer run,
// and prints a summary:
//
//	wbft-replay -journal DIR -chain FILE [-v]
//
// Without flags it speaks the line-based JSON protocol wbft-replay/1 on
// standard input and output, one object per line:
//
//	-> {"type":"hello","protocol":"wbft-replay/1"}
//	<- {"type":"hello","protocol":"wbft-replay/1","impl":"wbft"}
//	-> {"type":"replay","id":1,"journal":DIR,"chain":FILE,"from_step":0,"to_step":0,"with_vars":false}
//	<- {"type":"step","id":1,"engine_run":1,"step":1,"input":"start","out_digest":"0x..","match":true,"outputs":3}
//	<- {"type":"done","id":1,"steps":N,"mismatches":M}
//	-> {"type":"bye"}
//
// chain is a file of RLP-encoded canonical blocks from genesis (the
// chain.rlp of a simulator export). A failed request is answered with
// {"type":"error","id":ID,"error":TEXT}.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/buildmeta"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// Protocol is the protocol name of the standard input mode.
const Protocol = "wbft-replay/1"

func main() {
	jdir := flag.String("journal", "", "journal directory to replay")
	chain := flag.String("chain", "", "chain file (RLP list of blocks from genesis)")
	omit := flag.Bool("omit-missing-captures", false, "counterfactual: omit missing referenced peer inputs")
	answerScope := flag.String("answer-scope", "step", "recorded application answers: step or explicit counterfactual context")
	timerPolicyPath := flag.String("timer-policy", "", "counterfactual timer policy JSON with decimal string seconds")
	schedulePath := flag.String("input-schedule", "", "explicit counterfactual external-input schedule JSON")
	verbose := flag.Bool("v", false, "print every step")
	warmupFrom := flag.Uint64("warmup-from", 0, "first active height of explicit approximate warmup")
	compareFrom := flag.Uint64("compare-from", 0, "first comparison height after approximate warmup")
	flag.Parse()
	if *jdir != "" {
		if *timerPolicyPath != "" {
			if *answerScope != "context" || *schedulePath != "" || *omit || *warmupFrom != 0 || *compareFrom != 0 {
				fmt.Fprintln(os.Stderr, "wbft-replay: timer policy requires context answers and complete input")
				os.Exit(2)
			}
			policy, err := loadTimerPolicy(*timerPolicyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "wbft-replay:", err)
				os.Exit(2)
			}
			os.Exit(replayTimedOnce(*jdir, *chain, policy, os.Stdout))
		}
		opts := stepdriver.TraceOptions{OmitMissingCaptured: *omit, AnswerScope: *answerScope}
		if *schedulePath != "" {
			spec, err := loadSchedule(*schedulePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "wbft-replay:", err)
				os.Exit(2)
			}
			opts.Schedule = spec
		}
		if *warmupFrom != 0 || *compareFrom != 0 {
			opts.Warmup = &stepdriver.TraceWarmup{FromHeight: *warmupFrom, CompareFromHeight: *compareFrom}
		}
		os.Exit(replayOnceTrace(*jdir, *chain, *verbose, opts, os.Stdout))
	}
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wbft-replay:", err)
		os.Exit(1)
	}
}

func replayOnce(dir, chain string, verbose bool, w io.Writer) int {
	return replayOnceOptions(dir, chain, verbose, false, w)
}
func replayOnceOptions(dir, chain string, verbose, omit bool, w io.Writer) int {
	return replayOnceTrace(dir, chain, verbose, stepdriver.TraceOptions{OmitMissingCaptured: omit}, w)
}
func replayOnceTrace(dir, chain string, verbose bool, opts stepdriver.TraceOptions, w io.Writer) int {
	var steps, bad, approximate, warmup int
	err := replay(dir, chain, opts, func(s stepdriver.StepResult) error {
		steps++
		if s.Approximate {
			approximate++
		}
		if s.Warmup {
			warmup++
		}
		if !s.Match {
			bad++
		}
		if verbose || !s.Match {
			fmt.Fprintf(w, "run %d step %d %s match=%t outputs=%d approximate=%t warmup=%t\n", s.EngineRun, s.Step, inputlog.Kind(s.Input), s.Match, len(s.Outputs), s.Approximate, s.Warmup)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wbft-replay:", err)
		return 2
	}
	fmt.Fprintf(w, "steps %d mismatches %d\n", steps, bad)
	if steps == 0 {
		fmt.Fprintln(w, "no recorded engine start or replayed steps")
		return 2
	}
	if opts.Schedule != nil {
		fmt.Fprintln(w, "scheduled open-loop experiment; other nodes and application events follow the recording")
		return 3
	}
	if opts.AnswerScope == "context" {
		fmt.Fprintln(w, "context application answers; original reproduction is not established")
		return 3
	}
	if approximate > 0 {
		fmt.Fprintf(w, "approximate %d warmup %d; original reproduction is not established\n", approximate, warmup)
		return 3
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func replay(dir, chain string, opts stepdriver.TraceOptions, yield func(stepdriver.StepResult) error) error {
	b, err := os.ReadFile(chain)
	if err != nil {
		return err
	}
	blocks, err := sim.DecodeChain(b)
	if err != nil {
		return fmt.Errorf("chain file: %w", err)
	}
	src, err := sim.NewChainSource(blocks)
	if err != nil {
		return err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("journal %s: %w", dir, err)
	}
	if !st.IsDir() {
		// A journal bundle (wbft-journal export): extract it first.
		tmp, err := os.MkdirTemp("", "wbft-replay-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		m, err := journal.ReadBundle(f, fsys.OS{}, tmp)
		_ = f.Close()
		if err != nil {
			return err
		}
		if !m.StartsAtRunStart && opts.Warmup == nil {
			return fmt.Errorf("journal bundle %s does not start at the start of a writer run; its engine runs cannot be rebuilt", dir)
		}
		dir = tmp
	}
	r, err := journal.OpenReader(fsys.OS{}, dir)
	if err != nil {
		return err
	}
	if opts.AnswerScope == "context" {
		answers, err := journal.OpenReader(fsys.OS{}, dir)
		if err != nil {
			return err
		}
		opts.Answers, err = stepdriver.NewAnswerPool(answers)
		if err != nil {
			return err
		}
	}
	opts.Blocks = src
	return stepdriver.RunTrace(r, opts, yield)
}

type request struct {
	TimerPolicy *stepdriver.TimerPolicy   `json:"timer_policy,omitempty"`
	Schedule    *stepdriver.TraceSchedule `json:"input_schedule,omitempty"`
	AnswerScope string                    `json:"answer_scope"`
	Type        string                    `json:"type"`
	ID          uint64                    `json:"id"`
	Protocol    string                    `json:"protocol"`
	Journal     string                    `json:"journal"`
	Chain       string                    `json:"chain"`
	FromStep    uint64                    `json:"from_step"`
	ToStep      uint64                    `json:"to_step"`
	WithVars    bool                      `json:"with_vars"`
	OmitMissing bool                      `json:"omit_missing_captures"`
	WarmupFrom  uint64                    `json:"warmup_from_height"`
	CompareFrom uint64                    `json:"compare_from_height"`
}

// serve answers protocol requests until "bye" or the end of the input.
func serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	enc := json.NewEncoder(out)
	send := func(v any) error { return enc.Encode(v) }
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			if err := send(map[string]any{"type": "error", "error": "malformed request: " + err.Error()}); err != nil {
				return err
			}
			continue
		}
		switch req.Type {
		case "hello":
			if err := send(map[string]any{"type": "hello", "protocol": Protocol, "impl": "wbft", "version": buildmeta.Version(), "features": []string{"bounded_warmup_v1", "context_answers_v1", "input_schedule_v1", "timed_inputs_v1", "timed_state_v1", "timed_actions_v1"}}); err != nil {
				return err
			}
		case "timed_replay":
			if err := timedRequest(req, send); err != nil {
				return err
			}
		case "replay":
			if req.TimerPolicy != nil {
				if err := send(map[string]any{"type": "error", "id": req.ID, "code": "timer_policy", "error": "use timed_replay for timer policy experiments"}); err != nil {
					return err
				}
				continue
			}
			steps, bad, approximate, warmup := 0, 0, 0, 0
			opts := stepdriver.TraceOptions{Schedule: req.Schedule, AnswerScope: req.AnswerScope, FromStep: req.FromStep, ToStep: req.ToStep, WithVars: req.WithVars, OmitMissingCaptured: req.OmitMissing}
			if req.WarmupFrom != 0 || req.CompareFrom != 0 {
				opts.Warmup = &stepdriver.TraceWarmup{FromHeight: req.WarmupFrom, CompareFromHeight: req.CompareFrom}
			}
			err := replay(req.Journal, req.Chain, opts, func(s stepdriver.StepResult) error {
				steps++
				if s.Approximate {
					approximate++
				}
				if s.Warmup {
					warmup++
				}
				if !s.Match {
					bad++
				}
				m := map[string]any{"type": "step", "id": req.ID, "writer_run": s.WriterRun, "engine_run": s.EngineRun, "step": s.Step,
					"input": s.RecordedInputKind, "omitted": s.Omitted, "out_digest": "0x" + hex.EncodeToString(s.OutDigest[:]),
					"match": s.Match, "outputs": len(s.Outputs), "context_answers": s.ContextAnswers, "answer_sources": s.AnswerSources, "approximate": s.Approximate, "warmup": s.Warmup}
				if s.Scheduled != nil {
					m["scheduled_input"] = s.Scheduled
					m["suppression_reason"] = s.SuppressionReason
				}
				if s.Vars != nil {
					m["vars"] = json.RawMessage(stepdriver.VarsJSON(s.Vars))
				}
				return send(m)
			})
			if err != nil {
				code := "replay_error"
				if errors.Is(err, stepdriver.ErrTraceScheduleReservation) {
					code = "reservation_unavailable"
				} else if errors.Is(err, stepdriver.ErrTraceSchedule) {
					code = "input_schedule"
				} else if errors.Is(err, stepdriver.ErrTraceGap) || errors.Is(err, stepdriver.ErrTraceNoSegment) || errors.Is(err, stepdriver.ErrTraceMissingInput) || errors.Is(err, stepdriver.ErrTraceInvalidInput) {
					code = "input_gap"
				} else if errors.Is(err, stepdriver.ErrTraceWarmupUnavailable) {
					code = "warmup_unavailable"
				} else if errors.Is(err, stepdriver.ErrTraceEnvAmbiguous) {
					code = "env_ambiguous"
				} else if errors.Is(err, stepdriver.ErrTraceEnvSource) {
					code = "env_source_mismatch"
				} else if errors.Is(err, stepdriver.ErrTraceHeadMismatch) {
					code = "head_mismatch"
				} else if errors.Is(err, stepdriver.ErrTraceAnswerLimit) {
					code = "answer_limit"
				} else if errors.Is(err, stepdriver.ErrTraceEnvExhausted) {
					code = "env_exhausted"
				}
				reply := map[string]any{"type": "error", "id": req.ID, "code": code, "error": err.Error()}
				var failed *stepdriver.TraceError
				if errors.As(err, &failed) {
					reply["writer_run"] = failed.WriterRun
					reply["engine_run"] = failed.EngineRun
					reply["step"] = failed.Step
					reply["approximate"] = failed.Approximate
				}
				if err := send(reply); err != nil {
					return err
				}
				continue
			}
			if err := send(map[string]any{"type": "done", "id": req.ID, "steps": steps, "mismatches": bad, "counterfactual": req.Schedule != nil || req.OmitMissing || req.AnswerScope == "context", "input_schedule": req.Schedule, "answer_scope": req.AnswerScope, "approximate_steps": approximate, "warmup_steps": warmup}); err != nil {
				return err
			}
		case "bye":
			return nil
		default:
			if err := send(map[string]any{"type": "error", "id": req.ID, "error": "unknown request type " + req.Type}); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func loadSchedule(path string) (*stepdriver.TraceSchedule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, stepdriver.ErrTraceSchedule
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var out stepdriver.TraceSchedule
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return nil, stepdriver.ErrTraceSchedule
	}
	return &out, nil
}
