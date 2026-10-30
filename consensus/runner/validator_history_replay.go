package runner

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type validatorHistoryStep struct {
	deferred *deferredRecord
	input    inputRec
	index    uint64
	env      [][]byte
	intent   *validatorHistoryControl
	outs     []consensus.Output
	own      []ownRec
	commits  []wal.Record
	effects  []uint8
}

// validatorHistoryReplay is a full functional-prefix reconstruction. It does
// not reconstruct peer/application queues, physical workers or signer state.
type validatorHistoryReplay struct {
	core           *consensus.State
	head           *types.Header
	anchor, prefix types.Hash
	records, bytes uint64
	timers         [5]*consensus.ArmTimer
	lastOwn        map[ownKey][]byte
	pending        []deferredRecord
	state          WALState
	steps          uint64
	lastAdmission  uint64
}

func (p *validatorHistoryReplay) reference(c validatorHistoryControl) bool {
	return c.Anchor == p.anchor && c.Prefix == p.prefix && c.Records == p.records && c.Bytes == p.bytes
}

func (p *validatorHistoryReplay) advance(record wal.Record) error {
	n, err := validatorHistoryFrameBytes(record)
	if err != nil {
		return err
	}
	p.prefix, err = validatorHistoryPrefix(p.prefix, record)
	if err != nil {
		return err
	}
	p.records++
	p.bytes += n
	return nil
}

func sameValidatorHistoryView(a, b validatorHistoryView) bool {
	av, ae := a.value()
	bv, be := b.value()
	return ae == nil && be == nil && a.Adopted == b.Adopted && av.Cmp(bv) == 0
}

func validatorHistoryHeadBytes(head *types.Header) []byte {
	encoded, _ := codec.EncodeHeader(head)
	return encoded
}

func validatorHistoryMatchesCore(c validatorHistoryControl, core *consensus.State) bool {
	wait, err := validatorHistoryWaitBytes(core.ValidatorStartWait())
	return err == nil && slices.Equal(c.After, core.TimerGenerations()) &&
		sameValidatorHistoryView(c.AfterView, validatorHistoryAdoption(core)) && bytes.Equal(c.Wait, wait)
}

func validatorHistoryTrack(timers *[5]*consensus.ArmTimer, in consensus.Input, outs []consensus.Output) error {
	if timeout, ok := in.(consensus.Timeout); ok {
		if int(timeout.Kind) >= len(timers) {
			return errValidatorHistoryProfile
		}
		if old := timers[timeout.Kind]; old != nil && old.Gen == timeout.Gen && old.View.Cmp(timeout.View) == 0 && old.Round.Cmp(timeout.Round) == 0 {
			timers[timeout.Kind] = nil
		}
	}
	for _, out := range outs {
		switch o := out.(type) {
		case consensus.ArmTimer:
			if int(o.Kind) >= len(timers) {
				return errValidatorHistoryProfile
			}
			a := o
			timers[o.Kind] = &a
		case consensus.CancelTimers:
			for _, kind := range o.Kinds {
				if int(kind) >= len(timers) {
					return errValidatorHistoryProfile
				}
				timers[kind] = nil
			}
		}
	}
	return nil
}

func validatorHistorySeedOutputs(outs []consensus.Output) error {
	for _, out := range outs {
		switch out.(type) {
		case consensus.Broadcast, consensus.Commit, consensus.Relay, consensus.Schedule:
			return errValidatorHistoryProfile
		}
	}
	return nil
}

// validatorHistoryInner retains exact legacy wrappers when the processed head
// and adopted height admit such a boundary. A suspended/nonmatching head has
// no synthetic prior certificate; its outer profile is the replay authority.
func validatorHistoryInner(cfg Config, kind uint8, c validatorHistoryControl, core *consensus.State, pending []deferredRecord) (wal.Record, error) {
	if kind != walRunStart && kind != walEndHeight || core.ValidatorStartWait() != nil {
		return wal.Record{}, nil
	}
	head, err := codec.DecodeHeader(c.Head)
	view, adopted := core.AdoptedView()
	if err != nil || !adopted {
		return wal.Record{}, errValidatorHistoryProfile
	}
	if view.Sequence.Cmp(head.Number.AddUint64(1)) != 0 {
		return wal.Record{}, nil
	}
	snap := core.Snapshot()
	r := &Runner{cfg: cfg}
	if cfg.NextHeight != nil {
		r.nextHeight = newNextHeightPoolWithDomain(*cfg.NextHeight, cfg.Core.RoundChangeDomain)
		for _, d := range pending {
			r.nextHeight.order = append(r.nextHeight.order, d.ID)
			r.nextHeight.entries[d.ID] = &deferredEntry{record: d, stage: deferredPending}
		}
	}
	b := boundaryRec{From: view.Sequence, Head: head, Validators: snap.Validators, PriorSource: snap.PriorSource,
		Replayed: c.Mode != validatorControlSeed, LocalTimer: cfg.Core.Improvements.Has(consensus.ValidateRoundProposals)}
	copy(b.Gens[:], c.Before)
	if b.LocalTimer {
		b.LocalGen = c.Before[3]
	}
	return r.encodeRunnerBoundary(kind, b)
}

func validatorHistoryCheckInner(cfg Config, kind uint8, c validatorHistoryControl, core *consensus.State, pending []deferredRecord) error {
	expected, err := validatorHistoryInner(cfg, kind, c, core, pending)
	if err != nil {
		return err
	}
	if c.InnerFormat != uint64(expected.Format) || !bytes.Equal(c.Inner, expected.Body) {
		return errValidatorHistoryProfile
	}
	return nil
}

func validatorHistoryRun(core *consensus.State, head *types.Header, in consensus.Input, c validatorHistoryControl) ([]consensus.Output, error) {
	if timer, ok := in.(consensus.Timeout); ok && int(timer.Kind) >= len(core.TimerGenerations()) {
		return nil, errValidatorHistoryProfile
	}
	if !slices.Equal(c.Before, core.TimerGenerations()) || !sameValidatorHistoryView(c.BeforeView, validatorHistoryAdoption(core)) {
		return nil, errValidatorHistoryProfile
	}
	env := &replayEnv{head: head, strict: true}
	for _, witness := range c.Environment {
		call, err := witness.call()
		if err != nil {
			return nil, err
		}
		env.answers = append(env.answers, call)
	}
	outs := core.Step(env, in)
	digest, err := inputlog.OutDigest(outs)
	if err != nil || env.err != nil || len(env.answers) != 0 || digest != c.Outputs || !validatorHistoryMatchesCore(c, core) {
		return nil, errValidatorHistoryProfile
	}
	return outs, nil
}

func validatorHistorySameStep(a, b validatorHistoryControl) bool {
	// Prefix references and an optional compatible inner boundary belong to
	// each physical control, while these fields describe the same pure Step.
	return a.InputRecord == b.InputRecord && a.InputKind == b.InputKind && a.InputHash == b.InputHash &&
		bytes.Equal(a.Head, b.Head) && slices.Equal(a.Before, b.Before) && slices.Equal(a.After, b.After) &&
		sameValidatorHistoryView(a.BeforeView, b.BeforeView) && sameValidatorHistoryView(a.AfterView, b.AfterView) &&
		bytes.Equal(a.Wait, b.Wait) && a.Outputs == b.Outputs
}

func validatorHistoryCompareCommits(outs []consensus.Output, records []wal.Record) ([]CommitRequest, error) {
	var commits []CommitRequest
	for _, out := range outs {
		if c, ok := out.(consensus.Commit); ok {
			if len(records) == 0 {
				return nil, errValidatorHistoryProfile
			}
			expected, err := encodeCommit(c.Block, c.Round)
			if err != nil || records[0].Format != expected.Format || !bytes.Equal(records[0].Body, expected.Body) {
				return nil, errValidatorHistoryProfile
			}
			records = records[1:]
			commits = append(commits, CommitRequest{Block: c.Block, Round: c.Round})
		}
	}
	if len(records) != 0 {
		return nil, errValidatorHistoryProfile
	}
	return commits, nil
}

func validatorHistoryEffects(outs []consensus.Output, effects []uint8) bool {
	for _, out := range outs {
		var kind uint8
		switch out.(type) {
		case consensus.Broadcast:
			kind = walOwnMsg
		case consensus.Commit:
			kind = walCommit
		default:
			continue
		}
		if len(effects) == 0 || effects[0] != kind {
			return false
		}
		effects = effects[1:]
	}
	return len(effects) == 0
}

func decodeValidatorHistoryOwn(record wal.Record) (ownRec, error) {
	var own ownRec
	if rlp.DecodeStrict(record.Body, &own) != nil || own.Seq == nil || own.Round == nil || own.Refused > 1 || !bytes.Equal(encodeOwn(own).Body, record.Body) ||
		own.Refused == 0 && (len(own.Payload) == 0 || own.Seq.Sign() != 0 || own.Round.Sign() != 0) ||
		own.Refused == 1 && (len(own.Payload) != 0 || own.Seq.Sign() <= 0) {
		return own, errValidatorHistoryProfile
	}
	return own, nil
}

// parseValidatorHistory validates and executes the original entire prefix.
// The input is detached records, never a rewritten or truncated stored log.
// Callers must reject any ReadAll error before calling it.
func parseValidatorHistory(cfg Config, records []wal.Record, positions []wal.Position) (*validatorHistoryReplay, error) {
	return parseValidatorHistoryWithSteps(cfg, records, positions, nil)
}

// The internal collector builds journal data from verified replayed Steps.
// Startup publishes it only after the entire prefix and resume sync succeed.
func parseValidatorHistoryWithSteps(cfg Config, records []wal.Record, positions []wal.Position, note func(*journal.StepRec)) (*validatorHistoryReplay, error) {
	options, err := validatorHistoryOptionsBytes(cfg)
	if err != nil {
		return nil, err
	}
	limits, err := validatorHistoryLimits(cfg.ValidatorHistory)
	if err != nil || limits.Bytes <= validatorHistoryHaltBytes || limits.Records <= validatorHistoryHaltCount {
		return nil, errValidatorHistoryBudget
	}
	if len(positions) != 0 && len(positions) != len(records) {
		return nil, errValidatorHistoryProfile
	}
	p := &validatorHistoryReplay{core: consensus.NewState(cfg.Core), lastOwn: map[ownKey][]byte{}}
	if len(records) == 0 {
		return p, nil
	}
	var cur *validatorHistoryStep
	pending := map[uint64]deferredRecord{}
	var lastAdmission uint64
	var admissionPool *nextHeightPool
	if cfg.NextHeight != nil {
		admissionPool = newNextHeightPoolWithDomain(*cfg.NextHeight, cfg.Core.RoundChangeDomain)
	}
	ordered := func() []deferredRecord {
		out := make([]deferredRecord, 0, len(pending))
		for _, d := range pending { //wbft:unordered sorted by admission ID below
			out = append(out, d)
		}
		slices.SortFunc(out, func(a, b deferredRecord) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		return out
	}
	recordStep := func(kind string, body []byte, env [][]byte, digest types.Hash, gens []uint64) {
		if note == nil {
			return
		}
		rec := &journal.StepRec{InputKind: kind, Input: bytes.Clone(body), Via: viaWAL,
			HeadNumber: p.head.Number, HeadHash: codec.BlockHash(p.head), OutDigest: digest,
			ValsetDigest: consensus.ValsetDigest(p.core.Snapshot().Validators), TimerGens: slices.Clone(gens)}
		for _, raw := range env {
			rec.Env = append(rec.Env, bytes.Clone(raw))
		}
		note(rec)
	}
	for index, rec := range records {
		n, err := validatorHistoryFrameBytes(rec)
		if err != nil {
			return nil, err
		}
		if p.bytes > limits.Bytes || n > limits.Bytes-p.bytes || p.records == limits.Records {
			return nil, errValidatorHistoryBudget
		}
		if len(positions) != 0 {
			pos := positions[index]
			if pos.Offset < 0 || index == 0 && pos.Offset != 0 {
				return nil, errValidatorHistoryProfile
			}
			if index > 0 {
				prev := positions[index-1]
				prevBytes, _ := validatorHistoryFrameBytes(records[index-1])
				if pos.Segment == prev.Segment && pos.Offset != prev.Offset+int64(prevBytes) ||
					pos.Segment != prev.Segment && (pos.Segment <= prev.Segment || pos.Offset != 0) {
					return nil, errValidatorHistoryProfile
				}
			}
		}
		if rec.Format == functionalHistoryFormat(cfg.Core) {
			c, err := decodeValidatorHistoryControl(rec)
			if err != nil {
				return nil, err
			}
			if index == 0 {
				if c.Mode != validatorControlSeed || !bytes.Equal(c.Options, options) {
					return nil, errValidatorHistoryProfile
				}
				p.head, err = codec.DecodeHeader(c.Head)
				if err != nil {
					return nil, err
				}
				body, _ := inputlog.Encode(consensus.Start{})
				hash, _ := validatorHistoryInputHash(inputlog.KindStart, body)
				if c.InputHash != hash {
					return nil, errValidatorHistoryProfile
				}
				outs, err := validatorHistoryRun(p.core, p.head, consensus.Start{}, c)
				if err != nil || validatorHistorySeedOutputs(outs) != nil {
					return nil, errValidatorHistoryProfile
				}
				if err := validatorHistoryCheckInner(cfg, rec.Kind, c, p.core, nil); err != nil {
					return nil, err
				}
				if err := validatorHistoryTrack(&p.timers, consensus.Start{}, outs); err != nil {
					return nil, err
				}
				var env [][]byte
				for _, witness := range c.Environment {
					env = append(env, witness.Bytes)
				}
				recordStep(inputlog.KindStart, body, env, c.Outputs, c.Before)
				p.anchor, err = validatorHistoryRecordHash(rec)
				if err != nil {
					return nil, err
				}
			} else {
				if !p.reference(c) {
					return nil, errValidatorHistoryProfile
				}
				switch c.Mode {
				case validatorControlHalt:
					if c.HaltReason == validatorHaltLimit {
						return nil, errValidatorHistoryBudget
					}
					return nil, errValidatorHistoryHalted
				case validatorControlResume:
					if cur != nil || !validatorHistoryMatchesCore(c, p.core) || !bytes.Equal(c.Head, validatorHistoryHeadBytes(p.head)) {
						return nil, errValidatorHistoryProfile
					}
					if err := validatorHistoryCheckInner(cfg, rec.Kind, c, p.core, ordered()); err != nil {
						return nil, err
					}
				case validatorControlIntent:
					if cur == nil || cur.intent != nil || c.InputRecord != cur.index || c.InputKind != cur.input.Kind || len(cur.env) != len(c.Environment) {
						return nil, errValidatorHistoryProfile
					}
					hash, _ := validatorHistoryInputHash(cur.input.Kind, cur.input.Body)
					if c.InputHash != hash {
						return nil, errValidatorHistoryProfile
					}
					for i, w := range c.Environment {
						if !bytes.Equal(cur.env[i], w.Bytes) {
							return nil, errValidatorHistoryProfile
						}
					}
					in, err := inputlog.Decode(cur.input.Kind, cur.input.Body, nil)
					if err != nil {
						return nil, err
					}
					if head, ok := in.(consensus.NewHead); ok {
						if head.Header == nil {
							return nil, errValidatorHistoryProfile
						}
						p.head = head.Header
					}
					if !bytes.Equal(c.Head, validatorHistoryHeadBytes(p.head)) {
						return nil, errValidatorHistoryProfile
					}
					cur.outs, err = validatorHistoryRun(p.core, p.head, in, c)
					if err != nil {
						return nil, err
					}
					before, _ := c.BeforeView.value()
					after, _ := c.AfterView.value()
					if c.BeforeView.Adopted == 1 && c.AfterView.Adopted == 1 && after.Sequence.Cmp(before.Sequence) > 0 {
						p.lastOwn = map[ownKey][]byte{}
					}
					if err := validatorHistoryTrack(&p.timers, in, cur.outs); err != nil {
						return nil, err
					}
					cur.intent = &c
				case validatorControlComplete:
					if cur == nil || cur.intent == nil || !validatorHistorySameStep(*cur.intent, c) || !validatorHistoryEffects(cur.outs, cur.effects) {
						return nil, errValidatorHistoryProfile
					}
					if err := compareOwnWithDomain(cur.outs, cur.own, p.lastOwn, cfg.Core.RoundChangeDomain, cfg.Core.Self); err != nil {
						return nil, err
					}
					commits, err := validatorHistoryCompareCommits(cur.outs, cur.commits)
					if err != nil {
						return nil, err
					}
					p.state.Commits = append(p.state.Commits, commits...)
					if err := validatorHistoryCheckInner(cfg, rec.Kind, c, p.core, ordered()); err != nil {
						return nil, err
					}
					if rec.Kind == walEndHeight {
						view, _ := c.AfterView.value()
						h, _ := view.Sequence.Sub(types.HeightFromUint64(1))
						p.state.LastEnd = &h
					}
					kind, body := cur.input.Kind, cur.input.Body
					if cur.deferred != nil {
						d := cur.deferred
						body, err = inputlog.EncodeDeferredMessage(d.message(), inputlog.CaptureOrigin{Run: d.CaptureRun, Capture: d.Capture})
						if err != nil {
							return nil, err
						}
						kind = inputlog.KindDeferredMessage
					}
					recordStep(kind, body, cur.env, c.Outputs, nil)
					p.steps++
					cur = nil
				default:
					return nil, errValidatorHistoryProfile
				}
			}
		} else {
			if index == 0 {
				return nil, errValidatorHistoryProfile
			}
			switch {
			case rec.Format == walFormat && rec.Kind == walInput:
				if cur != nil {
					return nil, errValidatorHistoryProfile
				}
				var input inputRec
				if rlp.DecodeStrict(rec.Body, &input) != nil || input.Kind == inputlog.KindStart || input.Kind == inputlog.KindStop {
					return nil, errValidatorHistoryProfile
				}
				if _, err := inputlog.Decode(input.Kind, input.Body, nil); err != nil {
					return nil, err
				}
				canonical := encodeInput(input.Kind, input.Body)
				if !bytes.Equal(canonical.Body, rec.Body) {
					return nil, errValidatorHistoryProfile
				}
				cur = &validatorHistoryStep{input: input, index: uint64(index) + 1}
			case rec.Format == walFormat && rec.Kind == walEnv:
				if cur == nil || cur.intent != nil {
					return nil, errValidatorHistoryProfile
				}
				cur.env = append(cur.env, bytes.Clone(rec.Body))
			case rec.Format == walFormat && rec.Kind == walOwnMsg:
				if cur == nil || cur.intent == nil {
					return nil, errValidatorHistoryProfile
				}
				own, err := decodeValidatorHistoryOwn(rec)
				if err != nil {
					return nil, err
				}
				cur.own = append(cur.own, own)
				cur.effects = append(cur.effects, walOwnMsg)
			case rec.Format == walFormat && rec.Kind == walCommit:
				if cur == nil || cur.intent == nil {
					return nil, errValidatorHistoryProfile
				}
				cur.commits = append(cur.commits, rec)
				cur.effects = append(cur.effects, walCommit)
			case rec.Format == nextHeightFormat && (rec.Kind == walDeferredAdmit || rec.Kind == walDeferredDrop || rec.Kind == walDeferredInput):
				if cur != nil || cfg.NextHeight == nil {
					return nil, errValidatorHistoryProfile
				}
				var d deferredRecord
				if rlp.DecodeStrict(rec.Body, &d) != nil || d.ID == 0 {
					return nil, errValidatorHistoryProfile
				}
				canonical, err := rlp.Encode(d)
				if err != nil || !bytes.Equal(canonical, rec.Body) {
					return nil, errValidatorHistoryProfile
				}
				old, exists := pending[d.ID]
				if rec.Kind == walDeferredAdmit {
					if exists || d.ID <= lastAdmission {
						return nil, errValidatorHistoryProfile
					}
					if err := admissionPool.insertRestoredDeferredLocked(d); err != nil {
						return nil, err
					}
					lastAdmission = d.ID
					pending[d.ID] = d
				} else {
					if !exists || !sameDeferred(old, d) {
						return nil, errValidatorHistoryProfile
					}
					delete(pending, d.ID)
					admissionPool.removeLocked(admissionPool.entries[d.ID])
					if rec.Kind == walDeferredInput {
						input, err := deferredInput(d)
						if err != nil {
							return nil, err
						}
						cur = &validatorHistoryStep{input: input, index: uint64(index) + 1, deferred: &d}
					}
				}
			default:
				return nil, errValidatorHistoryProfile
			}
		}
		if p.bytes+n > limits.Bytes-validatorHistoryHaltBytes || p.records+1 > limits.Records-validatorHistoryHaltCount {
			return nil, errValidatorHistoryBudget
		}
		if err := p.advance(rec); err != nil {
			return nil, err
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("%w: incomplete step", errValidatorHistoryProfile)
	}
	p.pending = ordered()
	p.lastAdmission = lastAdmission
	return p, nil
}
