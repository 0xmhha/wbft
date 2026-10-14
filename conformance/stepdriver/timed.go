package stepdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/manualclock"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

var ErrTraceTiming = errors.New("stepdriver: recorded entry timing unavailable or inconsistent")

const TimedExperimentModel = "recorded-external-slots/zero-generated-processing/recorded-signing-results/1"

var ErrTimerPolicy = errors.New("stepdriver: invalid timer policy")

// TimerPolicy replaces round timeout parameters at every recorded height.
// Nil fields preserve the source configuration, including its transitions.
type TimerPolicy struct {
	RequestTimeoutSeconds    *uint64 `json:"request_timeout_seconds,omitempty"`
	MaxRequestTimeoutSeconds *uint64 `json:"max_request_timeout_seconds,omitempty"`
}
type TimedOptions struct {
	Blocks   BlockSource
	Answers  *AnswerPool
	Policy   TimerPolicy
	Complete func(TimedCompletion) error
}

// TimedCompletion reports remaining work at the retained horizon. Pending
// inputs are not executed or promoted to an invented future source tail.
type TimedCompletion struct {
	Writer                                     string
	Engine, Execution                          uint64
	Mono                                       time.Duration
	PendingInternal, QueuedTimers, ArmedTimers int
	Counterfactual                             bool
	Model                                      string
	TimerTraceValidated                        bool
}
type TimedSource struct {
	Writer                string
	Engine, Step, Ordinal uint64
}

// TimedResult distinguishes source input comparisons from generated expiries.
// Generated timers have an arm source, never a manufactured source ordinal.
type TimedResult struct {
	Model              string
	Counterfactual     bool
	Execution          uint64
	Mono               time.Duration
	Source             *TimedSource
	Arm                *TimedSource
	ArmExecution       uint64
	Deadline           *time.Duration
	Cause              *TimedSource
	ParentExecution    uint64
	Evidence           *TimedSource
	ApplicationSources []TimedQuestionSource
	Generated          bool
	Suppression        string
	Result             StepResult
}
type timedSourceEntry struct {
	record *journal.StepRec
	source TimedSource
	config journal.CoreOptions
}

func timedConfig(raw []byte, p TimerPolicy) (*types.Config, error) {
	if p.RequestTimeoutSeconds != nil && (*p.RequestTimeoutSeconds == 0 || *p.RequestTimeoutSeconds > uint64(math.MaxInt64/int64(time.Second))) {
		return nil, ErrTimerPolicy
	}
	if p.MaxRequestTimeoutSeconds != nil && *p.MaxRequestTimeoutSeconds > uint64(math.MaxInt64/int64(time.Second)) {
		return nil, ErrTimerPolicy
	}
	if p.RequestTimeoutSeconds == nil && p.MaxRequestTimeoutSeconds == nil {
		return types.ParseChainConfig(raw)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return nil, ErrTimerPolicy
	}
	var anzeon map[string]json.RawMessage
	if json.Unmarshal(root["anzeon"], &anzeon) != nil {
		return nil, ErrTimerPolicy
	}
	patch := func(raw json.RawMessage) (json.RawMessage, error) {
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return nil, ErrTimerPolicy
		}
		if values == nil {
			values = map[string]json.RawMessage{}
		}
		if p.RequestTimeoutSeconds != nil {
			values["requestTimeoutSeconds"], _ = json.Marshal(*p.RequestTimeoutSeconds)
		}
		if p.MaxRequestTimeoutSeconds != nil {
			values["maxRequestTimeoutSeconds"], _ = json.Marshal(*p.MaxRequestTimeoutSeconds)
		}
		return json.Marshal(values)
	}
	var e error
	anzeon["wbft"], e = patch(anzeon["wbft"])
	if e != nil {
		return nil, e
	}
	if raw, ok := root["transitions"]; ok {
		var transitions []map[string]json.RawMessage
		if json.Unmarshal(raw, &transitions) != nil {
			return nil, ErrTimerPolicy
		}
		for _, t := range transitions {
			if w, ok := t["wbft"]; ok {
				t["wbft"], e = patch(w)
				if e != nil {
					return nil, e
				}
			}
		}
		root["transitions"], _ = json.Marshal(transitions)
	}
	root["anzeon"], _ = json.Marshal(anzeon)
	out, e := json.Marshal(root)
	if e != nil {
		return nil, e
	}
	return types.ParseChainConfig(out)
}
func timedEntries(j JournalReader, pool *AnswerPool, observed *observedTimers) ([]timedSourceEntry, error) {
	check := pool.session()
	var entries []timedSourceEntry
	var identity journal.CoreOptions
	writer := ""
	var seq, engine, last uint64
	var previous time.Duration
	bytesCount := 0
	for ordinal := uint64(1); ; ordinal++ {
		rec, e := j.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if ordinal > MaxAnswerRecords {
			return nil, ErrTraceAnswerLimit
		}
		if seg, ok := rec.Body.(*journal.SegmentRec); ok {
			if e = check.validateSegment(seg); e != nil {
				return nil, e
			}
			if writer != seg.Run {
				seq, engine, last, previous = 0, 0, 0, 0
			}
			writer = seg.Run
			identity = seg.Core
		}
		if rec.JSeq == 0 || seq != 0 && rec.JSeq != seq+1 {
			return nil, ErrTraceGap
		}
		seq = rec.JSeq
		switch b := rec.Body.(type) {
		case *journal.TimerRec:
			if len(observed.records[writer]) >= MaxAnswerRecords {
				return nil, ErrTraceAnswerLimit
			}
			bytesCount += len(b.Input) + 256
			if bytesCount > MaxScheduledInputBytes {
				return nil, ErrTraceAnswerLimit
			}
			observed.records[writer] = append(observed.records[writer], b)
		case *journal.GapRec:
			return nil, ErrTraceGap
		case *journal.StepRec:
			if len(entries) >= MaxAnswerSteps {
				return nil, ErrTraceAnswerLimit
			}
			if b.Entry == nil || b.Entry.Mono < previous || b.Entry.Mono < 0 || b.Entry.Mono > b.Mono || b.Via == "wal" {
				return nil, ErrTraceTiming
			}
			if b.InputKind == inputlog.KindStart {
				engine, last = b.EngineRun, b.Step-1
			}
			if writer == "" || engine == 0 || b.EngineRun != engine || b.Step != last+1 {
				return nil, ErrTraceGap
			}
			last = b.Step
			previous = b.Mono
			bytesCount += len(b.Input)
			for _, x := range b.Env {
				bytesCount += len(x)
			}
			if bytesCount > MaxScheduledInputBytes {
				return nil, ErrTraceAnswerLimit
			}
			if _, e = check.source(writer, b); e != nil {
				return nil, e
			}
			entries = append(entries, timedSourceEntry{b, TimedSource{writer, b.EngineRun, b.Step, ordinal}, identity})
		}
	}
	if len(entries) == 0 {
		return nil, ErrTraceNoSegment
	}
	return entries, nil
}

// RunTimedTrace keeps recorded external execution slots and regenerates timer
// inputs between them with the official clock and runner expiry queue. Source
// processing slots are an explicit open-loop assumption, not receipt times.
func RunTimedTrace(j JournalReader, opts TimedOptions, yield func(TimedResult) error) error {
	if j == nil || opts.Answers == nil || opts.Blocks == nil || yield == nil {
		return ErrTraceTiming
	}
	observed := newObservedTimers()
	entries, e := timedEntries(j, opts.Answers, observed)
	if e != nil {
		return e
	}
	if e = observed.validate(entries); e != nil {
		return e
	}
	baseline := opts.Policy.RequestTimeoutSeconds == nil && opts.Policy.MaxRequestTimeoutSeconds == nil
	var reference map[TimedSource][]consensus.Output
	bySource := map[TimedSource]timedSourceEntry{}
	for _, entry := range entries {
		bySource[entry.source] = entry
	}
	signing := map[timedOutputKey]timedSigningEvidence{}
	var validated []TimedResult
	var baselineCompletions []TimedCompletion
	{
		reference = make(map[TimedSource][]consensus.Output, len(entries))
		var referenceBytes int
		type reserved struct {
			key    timedOutputKey
			output consensus.Output
		}
		var pending []reserved
		base := opts
		base.Policy = TimerPolicy{}
		base.Complete = func(result TimedCompletion) error {
			baselineCompletions = append(baselineCompletions, result)
			return nil
		}
		if e = runTimedEntries(entries, j, base, nil, nil, observed, func(r TimedResult) error {
			if r.Source == nil || !r.Result.Match {
				return ErrTraceScheduleReservation
			}
			entry := bySource[*r.Source]
			if err := observed.validateOutputs(entry, r.Result.Outputs); err != nil {
				return err
			}
			if baseline {
				validated = append(validated, r)
			}
			if entry.record.InputKind == inputlog.KindStart {
				pending = nil
			}
			if entry.record.Via == "internal" {
				if m, ok := r.Result.Input.(consensus.Message); ok && m.Peer != entry.config.Self {
					return ErrTraceScheduleReservation
				}
				if len(pending) == 0 {
					return ErrTraceScheduleReservation
				}
				reservation := pending[0]
				pending = pending[1:]
				match, err := matchesInternal(reservation.output, r.Result.Input)
				if err != nil {
					return err
				}
				if !match {
					return ErrTraceScheduleReservation
				}
				if b, ok := reservation.output.(consensus.Broadcast); ok {
					signing[reservation.key] = timedSigningEvidence{b, r.Result.Input, *r.Source}
				}
			}
			for i, output := range r.Result.Outputs {
				switch output.(type) {
				case consensus.Schedule, consensus.Broadcast:
					if len(pending) >= MaxReservedInputs {
						return ErrTraceAnswerLimit
					}
					pending = append(pending, reserved{timedOutputKey{*r.Source, i}, output})
				}
			}
			raw, err := inputlog.EncodeOutputs(r.Result.Outputs)
			if err != nil {
				return err
			}
			if len(raw) > MaxScheduledInputBytes-referenceBytes {
				return ErrTraceAnswerLimit
			}
			referenceBytes += len(raw)
			reference[*r.Source] = r.Result.Outputs
			return nil
		}); e != nil {
			return e
		}
	}
	if baseline {
		for _, result := range validated {
			if err := yield(result); err != nil {
				return err
			}
		}
		if opts.Complete != nil {
			if len(baselineCompletions) == 0 {
				return ErrTraceTiming
			}
			for _, completion := range baselineCompletions {
				if err := opts.Complete(completion); err != nil {
					return err
				}
			}
			return nil
		}
		return nil
	}
	pool, err := newTimedSigningPool(signing, bySource)
	if err != nil {
		return err
	}
	return runTimedEntries(entries, j, opts, reference, pool, observed, yield)
}

func runTimedEntries(entries []timedSourceEntry, j JournalReader, opts TimedOptions, reference map[TimedSource][]consensus.Output, signing *timedSigningPool, observed *observedTimers, yield func(TimedResult) error) error {
	var e error
	questions, err := newTimedQuestionPool(entries, reference)
	if err != nil {
		return err
	}
	var state *consensus.State
	var cfg *types.Config
	var head *types.Header
	var self types.Address
	var writer string
	var engine uint64
	var clock *manualclock.Clock
	var wallMono time.Duration
	var wallNs int64
	wallNow := func() int64 { return time.Unix(0, wallNs).Add(clock.Mono() - wallMono).UnixNano() }
	var queue *runner.TimerQueue
	var recordedClock *observedClock
	ledger := &reservationLedger{}
	ledger.reset()
	app := &timedApplicationLedger{}
	arms := map[[2]uint64]TimedSource{}
	armExecutions := map[[2]uint64]uint64{}
	armDeadlines := map[[2]uint64]time.Duration{}
	var internal []timedInternal
	var activeCause *TimedSource
	var activeParent uint64
	var activeEvidence *TimedSource
	session := opts.Answers.session()
	execution := uint64(0)
	emit := func(in consensus.Input, source *TimedSource, arm *TimedSource, original *journal.StepRec, mono time.Duration, suppression string) (emitErr error) {
		var parent uint64
		var deadline *time.Duration
		if timeout, ok := in.(consensus.Timeout); ok {
			parent = armExecutions[[2]uint64{uint64(timeout.Kind), timeout.Gen}]
			if d, ok := armDeadlines[[2]uint64{uint64(timeout.Kind), timeout.Gen}]; ok {
				deadline = &d
			}
		}
		defer func() {
			if emitErr != nil {
				cause := activeCause
				if cause == nil {
					cause = arm
				}
				parentExecution := activeParent
				if parentExecution == 0 {
					parentExecution = parent
				}
				emitErr = &TimedError{Execution: execution, Source: source, Cause: cause, ParentExecution: parentExecution, Err: emitErr}
			}
		}()
		execution++
		if execution > MaxAnswerSteps {
			return ErrTraceAnswerLimit
		}
		result := StepResult{ContextAnswers: true, Outputs: []consensus.Output{}}
		var applicationSources []TimedQuestionSource
		if suppression != "" {
			result, e = scheduledEmpty(state, original, true, suppression)
		} else {
			env := &traceEnv{cfg: cfg, blocks: opts.Blocks, head: head, session: session, source: answerStep{context: answerContext{writer, engine, head.Number.String(), codec.BlockHash(head), consensus.ValsetDigest(state.Snapshot().Validators)}}}
			if original != nil {
				known, err := session.source(writer, original)
				if err != nil {
					return err
				}
				if known.context == env.source.context {
					env.source = known
				}
			}
			if reference == nil {
				if original == nil {
					return ErrTraceTiming
				}
				env.session = nil
				for _, raw := range original.Env {
					answer, err := inputlog.DecodeEnv(raw)
					if err != nil {
						return err
					}
					env.answers = append(env.answers, answer)
				}
				result.ContextAnswers = false
			}
			result.Input = in
			result.Outputs = state.Step(env, in)
			if env.err != nil {
				return env.err
			}
			result.EnvCalls = env.calls
			result.AnswerSources = env.sources
			result.OutDigest, e = inputlog.OutDigest(result.Outputs)
			if e != nil {
				return e
			}
			if original != nil {
				result.RecordedInputKind = original.InputKind
				result.Step = original.Step
				result.Match = result.OutDigest == original.OutDigest && consensus.ValsetDigest(state.Snapshot().Validators) == original.ValsetDigest
			}
			if e = ledger.produced(result.Outputs); e != nil {
				return e
			}
			questionContext := answerContext{writer, engine, head.Number.String(), codec.BlockHash(head), consensus.ValsetDigest(state.Snapshot().Validators)}
			recorded, sources, err := questions.match(questionContext, result.Outputs)
			if err != nil {
				return err
			}
			applicationSources = sources
			if err := app.produced(result.Outputs, recorded, reference == nil, wallNow()); err != nil {
				return err
			}
			for outputIndex, o := range result.Outputs {
				cause := source
				if cause == nil {
					cause = activeCause
				}
				if cause == nil {
					cause = arm
				}
				if reference != nil {
					switch out := o.(type) {
					case consensus.Schedule:
						if len(internal) >= MaxReservedInputs {
							return ErrTraceAnswerLimit
						}
						internal = append(internal, timedInternal{Input: out.In, Cause: cause, ParentExecution: execution})
					case consensus.Broadcast:
						if len(internal) >= MaxReservedInputs {
							return ErrTraceAnswerLimit
						}
						proof, known, err := signing.take(out, writer, engine, codec.BlockHash(head))
						if err != nil {
							return err
						}
						if !known {
							internal = append(internal, timedInternal{Broadcast: &out, Cause: cause, ParentExecution: execution})
						} else {
							input := proof.Input
							if m, ok := input.(consensus.Message); ok {
								m.RecvMono = mono
								input = m
							}
							evidence := proof.Source
							internal = append(internal, timedInternal{Input: input, Cause: cause, ParentExecution: execution, Evidence: &evidence})
						}
					}
				}
				var operation *journal.TimerRec
				if reference == nil {
					switch o.(type) {
					case consensus.ArmTimer, consensus.CancelTimers:
						if source == nil {
							return ErrTraceTiming
						}
						operation = observed.operations[observedArmKey{source.Writer, source.Engine, source.Step, uint64(outputIndex) + 1}]
						if operation == nil || operation.Mono < clock.Mono() {
							return ErrTraceTiming
						}
						clock.AdvanceTo(operation.Mono)
					}
				}
				switch o := o.(type) {
				case consensus.ArmTimer:
					if o.Duration < 0 || o.Duration > time.Duration(math.MaxInt64)-mono {
						return ErrTimerPolicy
					}
					if reference == nil {
						raw, err := inputlog.Encode(consensus.Timeout{Kind: o.Kind, View: o.View, Round: o.Round, Gen: o.Gen, Msg: o.Msg})
						if err != nil {
							return err
						}
						if operation.Action != "arm" || operation.Deadline != mono+o.Duration || !bytes.Equal(operation.Input, raw) {
							return ErrTraceTiming
						}
						recordedClock.next = observed.arms[observedArmKey{source.Writer, source.Engine, source.Step, uint64(outputIndex) + 1}]
					}
					queue.Arm(o, mono)
					if recordedClock != nil && recordedClock.err != nil {
						return recordedClock.err
					}
					armExecutions[[2]uint64{uint64(o.Kind), o.Gen}] = execution
					armDeadlines[[2]uint64{uint64(o.Kind), o.Gen}] = mono + o.Duration
					if source != nil {
						arms[[2]uint64{uint64(o.Kind), o.Gen}] = *source
					} else if cause != nil {
						arms[[2]uint64{uint64(o.Kind), o.Gen}] = *cause
					}
				case consensus.CancelTimers:
					if reference == nil {
						if operation.Action != "cancel" || len(operation.Kinds) != len(o.Kinds) {
							return ErrTraceTiming
						}
						for i, kind := range o.Kinds {
							if operation.Kinds[i] != uint64(kind) {
								return ErrTraceTiming
							}
						}
					}
					queue.Cancel(o.Kinds)
				}
			}
		}
		result.WriterRun = writer
		result.EngineRun = engine
		cause, causalParent := activeCause, activeParent
		if cause == nil {
			cause = arm
		}
		if causalParent == 0 {
			causalParent = parent
		}
		model := "recorded-order/measured-timers/1"
		if reference != nil {
			model = TimedExperimentModel
		}
		return yield(TimedResult{Model: model, Counterfactual: reference != nil, Deadline: deadline, ArmExecution: parent, Execution: execution, Mono: mono, Source: source, Arm: arm, Cause: cause, ParentExecution: causalParent, Evidence: activeEvidence, ApplicationSources: applicationSources, Generated: source == nil, Suppression: suppression, Result: result})
	}
	drainInternal := func(mono time.Duration) error {
		for len(internal) > 0 {
			q := internal[0]
			internal = internal[1:]
			if q.Broadcast != nil {
				return &TimedError{Execution: execution + 1, Cause: q.Cause, ParentExecution: q.ParentExecution, Err: ErrTraceSigningUnavailable}
			}
			allowed, err := ledger.allowed(q.Input, "internal", self)
			if err != nil {
				return err
			}
			if !allowed {
				return ErrTraceScheduleReservation
			}
			activeCause, activeParent, activeEvidence = q.Cause, q.ParentExecution, q.Evidence
			err = emit(q.Input, nil, nil, nil, mono, "")
			activeCause, activeParent, activeEvidence = nil, 0, nil
			if err != nil {
				return &TimedError{Execution: execution, Cause: q.Cause, ParentExecution: q.ParentExecution, Err: err}
			}
		}
		return nil
	}
	drain := func(mono time.Duration) error {
		clock.AdvanceTo(mono)
		for {
			if err := drainInternal(mono); err != nil {
				return err
			}
			timeout, ok := queue.Pop()
			if !ok {
				return nil
			}
			allowed, err := ledger.allowed(timeout, "timer", self)
			if err != nil {
				return err
			}
			if !allowed {
				return ErrTraceScheduleReservation
			}
			origin, exists := arms[[2]uint64{uint64(timeout.Kind), timeout.Gen}]
			if !exists {
				return ErrTraceScheduleReservation
			}
			if e = emit(timeout, nil, &origin, nil, mono, ""); e != nil {
				return e
			}
		}
	}
	finishScope := func() error {
		if opts.Complete != nil && clock != nil {
			status := queue.Status()
			model := "recorded-order/measured-timers/1"
			if reference != nil {
				model = TimedExperimentModel
			}
			if err := opts.Complete(TimedCompletion{Writer: writer, Engine: engine, Execution: execution, Mono: clock.Mono(), PendingInternal: len(internal), QueuedTimers: status.Queued, ArmedTimers: status.Armed, Counterfactual: reference != nil, Model: model, TimerTraceValidated: true}); err != nil {
				return err
			}
		}
		return nil
	}
	baseline := opts.Policy.RequestTimeoutSeconds == nil && opts.Policy.MaxRequestTimeoutSeconds == nil
	for _, entry := range entries {
		b := entry.record
		if writer != entry.source.Writer {
			if writer != "" {
				if err := finishScope(); err != nil {
					return err
				}
			}
			writer = entry.source.Writer
			clock = manualclock.New(time.Unix(0, b.Entry.WallNs).Add(-b.Entry.Mono))
			wallMono, wallNs = b.Entry.Mono, b.Entry.WallNs
			if reference == nil {
				recordedClock = &observedClock{Clock: clock}
				queue = runner.NewTimerQueue(recordedClock)
			} else {
				recordedClock = nil
				queue = runner.NewTimerQueue(clock)
			}
			state = nil
			cfg, e = timedConfig(entry.config.ChainConfig, opts.Policy)
			if e != nil {
				return e
			}
			self = entry.config.Self
			engine = 0
		}
		if b.InputKind == inputlog.KindStart {
			if state != nil {
				queue.Clear()
			}
			engine = b.EngineRun
			ledger.reset()
			app = &timedApplicationLedger{}
			internal = nil
			arms = map[[2]uint64]TimedSource{}
			armExecutions = map[[2]uint64]uint64{}
			armDeadlines = map[[2]uint64]time.Duration{}
			state = consensus.NewState(consensus.Options{Config: cfg, Self: self, Improvements: consensus.ImprovementSet(entry.config.Improvements), BacklogLimit: int(entry.config.BacklogLimit)})
			if len(b.TimerGens) != 0 {
				if len(b.TimerGens) != 3 {
					return ErrTraceInvalidInput
				}
				var gens [3]uint64
				copy(gens[:], b.TimerGens)
				state.RestoreTimerGens(gens)
			}
		}
		if state == nil {
			return ErrTraceNoSegment
		}
		if !baseline {
			if err := drainInternal(clock.Mono()); err != nil {
				return err
			}
		}
		if !baseline && queue.Pending() {
			if e = drain(clock.Mono()); e != nil {
				return e
			}
		}
		for !baseline {
			next, ok := clock.NextTime()
			if !ok || next > b.Entry.Mono {
				break
			}
			if e = drain(next); e != nil {
				return e
			}
		}
		clock.AdvanceTo(b.Entry.Mono)
		wallMono, wallNs = b.Entry.Mono, b.Entry.WallNs
		if b.InputKind == inputlog.KindTimeout {
			if baseline {
				recorded, err := decodeTraceInput(b, nil)
				if err != nil {
					return err
				}
				expected, ok := recorded.(consensus.Timeout)
				if !ok {
					return ErrTraceInvalidInput
				}
				actual, ok, err := queue.PopRecorded(expected)
				if err != nil {
					return err
				}
				if !ok {
					return ErrTraceScheduleReservation
				}
				allowed, err := ledger.allowed(actual, "timer", self)
				if err != nil {
					return err
				}
				if !allowed {
					return ErrTraceScheduleReservation
				}
				a, err := inputlog.Encode(actual)
				if err != nil {
					return err
				}
				z, err := inputlog.Encode(recorded)
				if err != nil {
					return err
				}
				if !bytes.Equal(a, z) {
					return ErrTraceScheduleReservation
				}
				origin, ok := arms[[2]uint64{uint64(actual.Kind), actual.Gen}]
				if !ok {
					return ErrTraceScheduleReservation
				}
				source := entry.source
				if e = emit(actual, &source, &origin, b, b.Entry.Mono, ""); e != nil {
					return e
				}
				clock.AdvanceTo(b.Mono)
				wallMono, wallNs = b.Mono, b.WallNs
			}
			continue
		}
		if !baseline && b.Via == "internal" {
			source := entry.source
			if err := emit(nil, &source, nil, b, b.Entry.Mono, "regenerated_internal"); err != nil {
				return err
			}
			continue
		}
		var captured *consensus.Message
		if b.InputKind == inputlog.KindCapturedMessage {
			m, err := resolveCaptured(j, writer, b)
			if err != nil {
				return err
			}
			captured = m
			reference, err := inputlog.CapturedReference(b.Input)
			if err != nil {
				return err
			}
			resolver, ok := j.(captureResolver)
			if !ok {
				return ErrTraceTiming
			}
			frame, err := resolver.ResolveCapture(writer, reference)
			if err != nil {
				return err
			}
			if frame.Record.Mono < 0 || frame.Record.Mono > b.Entry.Mono {
				return ErrTraceTiming
			}
		}
		in, err := decodeTraceInput(b, captured)
		if err != nil {
			return err
		}
		if nh, ok := in.(consensus.NewHead); ok && nh.Header != nil {
			if nh.Header.Number.Cmp(b.HeadNumber) != 0 || codec.BlockHash(nh.Header) != b.HeadHash {
				return ErrTraceHeadMismatch
			}
			head = nh.Header
		} else {
			recordedHead, err := headOf(opts.Blocks, b.HeadNumber, b.HeadHash)
			if err != nil {
				return err
			}
			if head != nil && b.InputKind != inputlog.KindStart && (head.Number.Cmp(recordedHead.Number) != 0 || codec.BlockHash(head) != codec.BlockHash(recordedHead)) {
				return ErrTraceHeadMismatch
			}
			head = recordedHead
		}
		if err := app.allowed(in, b.Via, head, wallNow()); err != nil {
			source := entry.source
			return &TimedError{Execution: execution + 1, Source: &source, Err: err}
		}
		allowed, err := ledger.allowed(in, b.Via, self)
		if err != nil {
			return err
		}
		reason := ""
		if !allowed {
			if baseline {
				return ErrTraceScheduleReservation
			}
			reason = "reservation_unavailable"
		}
		source := entry.source
		if e = emit(in, &source, nil, b, b.Entry.Mono, reason); e != nil {
			return e
		}
		// Retain measured source busy time. Expiries may queue during processing,
		// but a generated handler cannot execute before that processing ends.
		clock.AdvanceTo(b.Mono)
		wallMono, wallNs = b.Mono, b.WallNs
		if b.InputKind == inputlog.KindStop {
			for _, operation := range observed.lifecycle[answerCoordinate{writer, engine, b.Step}] {
				if operation.Mono < clock.Mono() {
					return ErrTraceTiming
				}
				clock.AdvanceTo(operation.Mono)
				wallMono, wallNs = operation.Mono, operation.WallNs
				switch operation.Action {
				case "cancel":
					var kinds []consensus.TimerKind
					for _, kind := range operation.Kinds {
						kinds = append(kinds, consensus.TimerKind(kind))
					}
					queue.Cancel(kinds)
				case "clear":
					queue.Clear()
					internal = nil
				default:
					return ErrTraceTiming
				}
			}
		}
	}
	if err := finishScope(); err != nil {
		return err
	}
	// Outputs remaining at the finite source horizon are not a recorded tail.
	// Do not execute them beyond that horizon or invent their signing answers.
	return nil
}
