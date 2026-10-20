package stepdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// BlockSource answers Head and ValidatorsAt of a trace replay from
// recorded block data.
type BlockSource interface {
	HeaderByNumber(n types.Height) (*types.Header, error)
	BlockByHash(h types.Hash) (*types.Block, error)
}

// JournalReader yields the records of a message journal in order;
// *journal.Reader is one.
type JournalReader interface {
	Next() (journal.Record, error)
}

// TraceOptions configure RunTrace.
type TraceOptions struct {
	// Schedule explicitly enables an open-loop external-input experiment.
	// Source continuity is checked before any altered input is executed.
	Schedule *TraceSchedule

	// AnswerScope context explicitly enables cross-step recorded application answers.
	// The caller supplies an AnswerPool built from the same retained source.
	AnswerScope string
	Answers     *AnswerPool
	// Warmup explicitly permits approximate state initialisation when the
	// recorded engine start is absent. Nil preserves closed replay behavior.
	Warmup *TraceWarmup
	// OmitMissingCaptured explicitly models intentional received-message loss.
	// The missing input is not fed; its actual empty output list is compared.
	// Default closed replay refuses missing captures instead.
	OmitMissingCaptured bool

	Blocks BlockSource
	// FromStep and ToStep limit the reported steps of every engine run
	// (0: from the start, to the end); every step is still fed.
	FromStep uint64
	ToStep   uint64
	// WithVars includes consensus.Vars after every step.
	WithVars bool
}

// TraceWarmup bounds an approximate prefix before the comparison height.
// The caller must keep approximate results distinct from original reproduction.
type TraceWarmup struct {
	FromHeight        uint64
	CompareFromHeight uint64
}

// StepResult is one replayed core Step.
type StepResult struct {
	Scheduled         *TraceInputPosition
	SuppressionReason string

	ContextAnswers bool
	AnswerSources  []AnswerSource
	// Approximate remains true until an actual recorded start resets the core.
	Approximate bool
	// Warmup reports an approximate step before CompareFromHeight.
	Warmup            bool
	WriterRun         string
	RecordedInputKind string
	Omitted           bool
	EngineRun         uint64
	Step              uint64
	Input             consensus.Input
	// EnvCalls are the Env calls the core made, with the answers given.
	EnvCalls  []inputlog.EnvCall
	Outputs   []consensus.Output
	OutDigest types.Hash
	// Match reports that OutDigest equals the recorded out_digest and the
	// validator set digest equals the recorded one.
	Match bool
	Vars  *consensus.Vars
}

// TraceError locates a failed input without parsing diagnostic text.
type TraceError struct {
	Approximate bool
	WriterRun   string
	EngineRun   uint64
	Step        uint64
	Err         error
}

func (e *TraceError) Error() string {
	return fmt.Sprintf("stepdriver: writer %s engine run %d step %d: %v", e.WriterRun, e.EngineRun, e.Step, e.Err)
}
func (e *TraceError) Unwrap() error { return e.Err }

// Errors of RunTrace.
var (
	ErrTraceConfiguration     = errors.New("stepdriver: inconsistent writer configuration")
	ErrTraceInvalidInput      = errors.New("stepdriver: captured input is invalid")
	ErrTraceMissingInput      = errors.New("stepdriver: captured input is unavailable")
	ErrTraceHeadMismatch      = errors.New("stepdriver: recorded head identity mismatch")
	ErrTraceEnvExhausted      = errors.New("stepdriver: recorded application answer unavailable")
	ErrTraceNoSegment         = errors.New("stepdriver: journal has no segment record before its steps")
	ErrTraceGap               = errors.New("stepdriver: journal steps are not contiguous")
	ErrTraceWarmupUnavailable = errors.New("stepdriver: bounded warmup prefix unavailable")
)

// RunTrace rebuilds consensus.State from the journal "segment" record and
// feeds the recorded steps in order: every "start" step creates a new core
// (with the timer generations the step records). Head and ValidatorsAt are
// answered from opts.Blocks, ValidateProposal and IsBadBlock from the
// answers the step records by call kind and argument key, CommitHeader by
// header.CommitHeader. Each writer uses its own recorded configuration. yield is
// called for every step within [FromStep, ToStep].
func RunTrace(j JournalReader, opts TraceOptions, yield func(StepResult) error) error {
	var answers *answerSession
	if opts.AnswerScope != "" && opts.AnswerScope != "step" && opts.AnswerScope != "context" {
		return ErrTraceEnvSource
	}
	if opts.AnswerScope == "context" {
		if opts.Answers == nil {
			return ErrTraceEnvSource
		}
		answers = opts.Answers.session()
	}
	if opts.Warmup != nil && (opts.Warmup.FromHeight == 0 || opts.Warmup.CompareFromHeight <= opts.Warmup.FromHeight || opts.Warmup.CompareFromHeight-opts.Warmup.FromHeight > 10000) {
		return ErrTraceWarmupUnavailable
	}
	var schedule *scheduledJournal
	if opts.Schedule != nil {
		if opts.AnswerScope != "context" || opts.OmitMissingCaptured || opts.Warmup != nil {
			return ErrTraceSchedule
		}
		var err error
		schedule, err = newScheduledJournal(j, *opts.Schedule)
		if err != nil {
			return err
		}
		j = schedule
	}
	ledger := &reservationLedger{}
	ledger.reset()
	changed := false
	var cfg *types.Config
	var copts consensus.Options
	var core *consensus.State
	var run, last uint64
	var writerRun string
	var configuration []byte
	approximate := false
	everStarted := false
	for {
		rec, err := j.Next()
		if err == io.EOF {
			if opts.Warmup != nil && !everStarted {
				return ErrTraceWarmupUnavailable
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			if answers != nil {
				if err := answers.validateSegment(b); err != nil {
					return err
				}
			}
			encoded, err := json.Marshal(b.Core)
			if err != nil {
				return err
			}
			if cfg != nil && b.Run == writerRun && !bytes.Equal(encoded, configuration) {
				return ErrTraceConfiguration
			}
			if cfg == nil || b.Run != writerRun {
				c, err := b.Core.Configuration()
				if err != nil {
					return fmt.Errorf("stepdriver: segment chain configuration: %w", err)
				}
				cfg = c
				copts = consensus.Options{Config: cfg, Self: b.Core.Self, Improvements: consensus.ImprovementSet(b.Core.Improvements), BacklogLimit: int(b.Core.BacklogLimit)}
				core = nil
				approximate = false
				run, last = 0, 0
				writerRun = b.Run
				configuration = encoded
			}

		case *journal.GapRec:
			// A readable step prefix cannot prove reproduction across lost inputs.
			return fmt.Errorf("%w: journal dropped %d records", ErrTraceGap, b.Dropped)
		case *journal.StepRec:
			original, slot := b, b
			var position *TraceInputPosition
			if schedule != nil {
				entry, ok := schedule.entries[b]
				if !ok {
					return ErrTraceSchedule
				}
				original, slot = entry.original, entry.slot
				p := entry.position
				position = &p
				if p.Removed || original.Step != slot.Step {
					changed = true
				}
			}
			if cfg == nil {
				return ErrTraceNoSegment
			}
			if answers != nil {
				if _, err := answers.source(writerRun, original); err != nil {
					return &TraceError{Approximate: approximate, WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: err}
				}
			}
			if b.Step == 0 {
				return &TraceError{Approximate: approximate, WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: ErrTraceGap}
			}
			if b.InputKind == inputlog.KindStart {
				approximate = false
				core = consensus.NewState(copts)
				ledger.reset()
				everStarted = true
				var g [3]uint64
				copy(g[:], b.TimerGens)
				core.RestoreTimerGens(g)
				run, last = b.EngineRun, b.Step-1
			}
			if core == nil {
				if opts.Warmup != nil {
					active, err := warmupHeight(b)
					if err != nil {
						return &TraceError{WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: err}
					}
					if active < opts.Warmup.FromHeight {
						continue
					}
					if active != opts.Warmup.FromHeight {
						return &TraceError{WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: ErrTraceWarmupUnavailable}
					}
					core, err = bootstrapWarmup(copts, cfg, opts.Blocks, b)
					if err != nil {
						return &TraceError{WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: err}
					}
					run, last = b.EngineRun, b.Step-1
					approximate = true
					everStarted = true
				} else {
					// Steps of an engine run whose start is not in the journal
					// (pruned or lost) cannot be replayed.
					continue
				}
			}
			if b.EngineRun != run || b.Step != last+1 {
				return &TraceError{Approximate: approximate, WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: fmt.Errorf("%w: after engine run %d step %d", ErrTraceGap, run, last)}
			}
			last = b.Step
			var captured *consensus.Message
			if b.InputKind == inputlog.KindCapturedMessage {
				var err error
				captured, err = resolveCaptured(j, writerRun, b)
				if err != nil {
					if !opts.OmitMissingCaptured || !errors.Is(err, ErrTraceMissingInput) {
						return &TraceError{Approximate: approximate, WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: err}
					}
					d, e := inputlog.OutDigest(nil)
					if e != nil {
						return e
					}
					result := StepResult{ContextAnswers: answers != nil, WriterRun: writerRun, RecordedInputKind: b.InputKind, Omitted: true, EngineRun: b.EngineRun, Step: b.Step, Outputs: []consensus.Output{}, OutDigest: d, Match: d == b.OutDigest && consensus.ValsetDigest(core.Snapshot().Validators) == b.ValsetDigest}
					if err = markWarmup(&result, b, opts.Warmup, approximate); err != nil {
						return err
					}
					if b.Step >= opts.FromStep && (opts.ToStep == 0 || b.Step <= opts.ToStep) {
						if e = yield(result); e != nil {
							return e
						}
					}
					continue
				}
			}
			var res StepResult
			var err error
			if schedule != nil {
				in, e := decodeTraceInput(original, captured)
				if e != nil {
					return &TraceError{WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: e}
				}
				reason := ""
				if position.Removed {
					reason = "requested_drop"
				} else {
					allowed, e := ledger.allowed(in, original.Via, copts.Self)
					if e != nil {
						return e
					}
					if !allowed {
						if !changed {
							return &TraceError{WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: ErrTraceScheduleReservation}
						}
						reason = "reservation_unavailable"
					}
				}
				if reason != "" {
					res, err = scheduledEmpty(core, original, answers != nil, reason)
				} else {
					res, err = replayStepExecution(core, cfg, opts.Blocks, original, captured, writerRun, answers, slot)
				}
				if err == nil {
					err = ledger.produced(res.Outputs)
				}
				res.Scheduled = position
			} else {
				res, err = replayStep(core, cfg, opts.Blocks, b, captured, writerRun, answers)
			}
			if err != nil {
				return &TraceError{Approximate: approximate, WriterRun: writerRun, EngineRun: original.EngineRun, Step: original.Step, Err: err}
			}
			res.WriterRun = writerRun
			if err = markWarmup(&res, original, opts.Warmup, approximate); err != nil {
				return err
			}
			if opts.WithVars {
				res.Vars = core.Vars()
			}
			if original.Step < opts.FromStep || opts.ToStep != 0 && original.Step > opts.ToStep {
				continue
			}
			if err := yield(res); err != nil {
				return err
			}
		}
	}
}

// replayStep feeds one recorded step to core.
func replayStep(core *consensus.State, cfg *types.Config, blocks BlockSource, b *journal.StepRec, captured *consensus.Message, writer string, session *answerSession) (StepResult, error) {
	return replayStepExecution(core, cfg, blocks, b, captured, writer, session, nil)
}
func replayStepExecution(core *consensus.State, cfg *types.Config, blocks BlockSource, b *journal.StepRec, captured *consensus.Message, writer string, session *answerSession, execution *journal.StepRec) (StepResult, error) {
	in, err := inputlog.Decode(b.InputKind, b.Input, func(uint64) ([]byte, error) {
		if captured == nil {
			return nil, ErrTraceMissingInput
		}
		return captured.Payload, nil
	})
	if err != nil {
		return StepResult{}, err
	}
	env := &traceEnv{cfg: cfg, blocks: blocks, session: session}
	if session != nil {
		env.source, err = session.source(writer, b)
		if err != nil {
			return StepResult{}, err
		}
	}
	if nh, ok := in.(consensus.NewHead); ok && nh.Header != nil {
		if session != nil && (nh.Header.Number.Cmp(b.HeadNumber) != 0 || codec.BlockHash(nh.Header) != b.HeadHash) {
			return StepResult{}, ErrTraceEnvSource
		}
		env.head = nh.Header
	} else {
		context := b
		if execution != nil {
			context = execution
		}
		env.head, err = headOf(blocks, context.HeadNumber, context.HeadHash)
		if err != nil {
			return StepResult{}, err
		}
	}
	if execution != nil && session != nil {
		current := answerContext{writer: writer, engine: b.EngineRun, head: env.head.Number.String(), hash: codec.BlockHash(env.head), valset: consensus.ValsetDigest(core.Snapshot().Validators)}
		if current != env.source.context {
			env.source.context = current
			env.source.entries = nil
		}
	}
	for _, e := range b.Env {
		c, err := inputlog.DecodeEnv(e)
		if err != nil {
			return StepResult{}, err
		}
		env.answers = append(env.answers, c)
	}
	outs := core.Step(env, in)
	if env.err != nil {
		return StepResult{}, env.err
	}
	d, err := inputlog.OutDigest(outs)
	if err != nil {
		return StepResult{}, err
	}
	vd := consensus.ValsetDigest(core.Snapshot().Validators)
	return StepResult{RecordedInputKind: b.InputKind, EngineRun: b.EngineRun, Step: b.Step, Input: in, ContextAnswers: session != nil, AnswerSources: env.sources, EnvCalls: env.calls, Outputs: outs, OutDigest: d,
		Match: d == b.OutDigest && vd == b.ValsetDigest}, nil
}

func headOf(blocks BlockSource, n types.Height, h types.Hash) (*types.Header, error) {
	if blocks == nil {
		return nil, errors.New("no block source")
	}
	matches := func(hd *types.Header) bool { return hd != nil && hd.Number.Cmp(n) == 0 && codec.BlockHash(hd) == h }
	hd, err := blocks.HeaderByNumber(n)
	if err == nil && matches(hd) {
		return hd, nil
	}
	b, err := blocks.BlockByHash(h)
	if err != nil {
		return nil, fmt.Errorf("head %s %x: %w", n, h[:4], err)
	}
	if b == nil || !matches(b.Header) {
		return nil, ErrTraceHeadMismatch
	}
	return b.Header, nil
}

// traceEnv answers a replayed step.
type traceEnv struct {
	session *answerSession
	source  answerStep
	sources []AnswerSource
	cfg     *types.Config
	blocks  BlockSource
	head    *types.Header
	answers []inputlog.EnvCall
	calls   []inputlog.EnvCall
	err     error
}

func (e *traceEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}

func (e *traceEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	vs, err := validator.ValidatorsAt(chainOf{e.blocks}, e.cfg, n, parent, nil)
	c := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: n, Key: parent, Validators: vs}
	if err != nil {
		c.Validators, c.Err = nil, err.Error()
	}
	e.calls = append(e.calls, c)
	return vs, err
}

func (e *traceEnv) pop(kind uint8, key types.Hash) (inputlog.EnvCall, bool) {
	if e.err != nil {
		return inputlog.EnvCall{}, false
	}
	if e.session != nil {
		c, source, err := e.session.pop(e.source, kind, key)
		if err != nil {
			e.err = err
			return inputlog.EnvCall{}, false
		}
		e.calls = append(e.calls, c)
		e.sources = append(e.sources, source)
		return c, true
	}
	for i, c := range e.answers {
		if c.Kind == kind && c.Key == key {
			e.answers = append(e.answers[:i], e.answers[i+1:]...)
			e.calls = append(e.calls, c)
			return c, true
		}
	}
	e.err = fmt.Errorf("%w: call %d on %x", ErrTraceEnvExhausted, kind, key[:4])
	return inputlog.EnvCall{}, false
}

func (e *traceEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	c, ok := e.pop(inputlog.EnvValidateProposal, codec.BlockHash(b.Header))
	if !ok {
		return 0, errors.New("stepdriver: no recorded proposal answer")
	}
	return c.ProposalAnswer()
}

func (e *traceEnv) IsBadBlock(h types.Hash) bool {
	c, ok := e.pop(inputlog.EnvIsBadBlock, h)
	return ok && c.Bad
}

func (e *traceEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}

// chainOf is a types.ChainReader over a BlockSource.
type chainOf struct{ b BlockSource }

func heightOf(idx uint64) types.Height { return types.HeightFromUint64(idx) }

func (c chainOf) Head() *types.Header { return nil }
func (c chainOf) HeaderByNumber(idx uint64) *types.Header {
	if c.b == nil {
		return nil
	}
	h, err := c.b.HeaderByNumber(heightOf(idx))
	if err != nil {
		return nil
	}
	return h
}
func (c chainOf) Header(hash types.Hash, idx uint64) *types.Header {
	h := c.HeaderByHash(hash)
	if h == nil || !h.Number.IsUint64() || h.Number.CmpUint64(idx) != 0 {
		return nil
	}
	return h
}
func (c chainOf) HeaderByHash(hash types.Hash) *types.Header {
	if c.b == nil {
		return nil
	}
	b, err := c.b.BlockByHash(hash)
	if err != nil {
		return nil
	}
	return b.Header
}
func (c chainOf) HasBlock(hash types.Hash, idx uint64) bool { return c.Header(hash, idx) != nil }

type captureResolver interface {
	ResolveCapture(run string, id uint64) (journal.CapturedFrame, error)
}

func resolveCaptured(reader JournalReader, run string, step *journal.StepRec) (*consensus.Message, error) {
	id, err := inputlog.CapturedReference(step.Input)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed reference", ErrTraceInvalidInput)
	}
	resolver, ok := reader.(captureResolver)
	if !ok {
		return nil, ErrTraceInvalidInput
	}
	frame, err := resolver.ResolveCapture(run, id)
	if err != nil {
		if errors.Is(err, journal.ErrCaptureMissing) {
			return nil, fmt.Errorf("%w: %v", ErrTraceMissingInput, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTraceInvalidInput, err)
	}
	data, code, action, _ := transport.DecodeFrame(frame.Record.Code, frame.Record.Payload)
	if action != transport.FrameDeliver {
		return nil, ErrTraceInvalidInput
	}
	input, err := inputlog.Decode(step.InputKind, step.Input, func(ref uint64) ([]byte, error) {
		if ref != id {
			return nil, ErrTraceMissingInput
		}
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	message, ok := input.(consensus.Message)
	if !ok || uint64(message.Code) != code || message.Peer != frame.Peer {
		return nil, ErrTraceInvalidInput
	}
	return &message, nil
}
