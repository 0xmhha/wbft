package journal

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

// RestoreCheck is conditional reconstruction of retained readable prefixes.
// Signature state, application execution and filesystem durability stay separate.
type RestoreCheck struct {
	Status                        string `json:"status"`
	Reason                        string `json:"reason,omitempty"`
	Scope                         string `json:"scope"`
	SignerStatus                  string `json:"signer_status"`
	ApplicationStatus             string `json:"application_status"`
	PhysicalStatus                string `json:"physical_status"`
	Reads, Runs, Attempts, Inputs uint64
	UnreferencedReads             uint64 `json:"unreferenced_reads,string"`
}

var ErrRestoreSource = errors.New("journal: inconsistent restore source")

// These private types decode the public WAL wire contract independently of the
// runner's planner and replay helpers. No runner-owned state or output is fed in.
type restoreBoundary struct {
	From           *big.Int
	Head           []byte
	HasSet, Policy uint64
	Addrs          []types.Address
	Keys           [][]byte
	Replayed       uint64
	Gens           []uint64
}
type restoreInput struct {
	Kind string
	Body []byte
}
type restoreOwnWire struct {
	Code       uint64
	Payload    []byte
	Refused    uint64
	Seq, Round *big.Int
}
type restoreStep struct {
	index     uint64
	in        restoreInput
	env       [][]byte
	own       []restoreOwnWire
	ownFrames []int
}
type restorePlan struct {
	boundary uint64
	head     *types.Header
	vs       *validator.Set
	gens     []uint64
	steps    []restoreStep
}
type restoredCoreSeed struct {
	model     *coreSourceRun
	ready     int
	config    coreSourceWriter
	timers    [4]*consensus.ArmTimer
	own       []RestoreOwn
	read      *WALReadRec
	readIndex int
	installed *RestoreRec
	ownFrames []int
}
type restoreRoots struct {
	read   *WALReadRec
	writer string
	index  int
}

// CheckRestoreSources verifies actual selection and every retained attempt. A
// successful result is not a general runtime or physical execution verdict.
func CheckRestoreSources(records []Record, limits CoreSourceLimits) (RestoreCheck, error) {
	report, _, err := reconstructRestoreSources(records, limits)
	return report, err
}

func reconstructRestoreSources(records []Record, limits CoreSourceLimits) (RestoreCheck, map[coreSourceRunKey]restoredCoreSeed, error) {
	report := RestoreCheck{Status: "unavailable", Scope: "restore_on_original_readable_prefix", SignerStatus: "unavailable", ApplicationStatus: "unavailable", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (RestoreCheck, map[coreSourceRunKey]restoredCoreSeed, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil, nil
	}
	bad := func(reason string) (RestoreCheck, map[coreSourceRunKey]restoredCoreSeed, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, nil, fmt.Errorf("%w: %s", ErrRestoreSource, reason)
	}
	if limits.Records == 0 || limits.Runs == 0 || limits.Steps == 0 || limits.Environments == 0 || limits.Outputs == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	reads := map[WALReadRef]restoreRoots{}
	seeds := map[coreSourceRunKey]restoredCoreSeed{}
	seen := map[coreSourceRunKey]bool{}
	usedReads := map[WALReadRef]bool{}
	configs := map[string]coreSourceWriter{}
	writer := ""
	var span, steps, environments, outputs uint64
	charge := func(n uint64) bool {
		if n > limits.Bytes-span {
			return false
		}
		span += n
		return true
	}
	for position, rec := range records {
		switch s := rec.Body.(type) {
		case *SegmentRec:
			writer = s.Run
			if writer == "" || len(s.Core.ChainConfig) == 0 {
				return unavailable("core_writer_missing")
			}
			if !charge(uint64(len(s.Core.ChainConfig))) {
				return unavailable("byte_limit")
			}
			w := coreSourceWriter{config: bytes.Clone(s.Core.ChainConfig), self: s.Core.Self, improvements: s.Core.Improvements, backlog: s.Core.BacklogLimit}
			if old, ok := configs[writer]; ok && (old.self != w.self || old.improvements != w.improvements || old.backlog != w.backlog || !bytes.Equal(old.config, w.config)) {
				return bad("writer_configuration_changed")
			}
			configs[writer] = w
		case *GapRec:
			if s.Dropped > 0 && len(s.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range s.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindWALRead) || k.Kind == uint64(KindRestore)) {
					return unavailable("restore_source_gap")
				}
			}
		case *WALReadRec:
			if uint64(len(s.Source.Frames)) > limits.Records {
				return unavailable("frame_limit")
			}
			for _, f := range s.Source.Frames {
				if !charge(uint64(len(f.Bytes))) {
					return unavailable("byte_limit")
				}
			}
			if !validWALReadRec(s) {
				return bad("invalid_original_read")
			}
			if s.Source.Unavailable != "" {
				return unavailable("original_read_" + s.Source.Unavailable)
			}
			if s.Source.Namespace != writer {
				return bad("read_writer_changed")
			}
			key := WALReadRef{s.Source.Namespace, s.Source.Log, s.Source.Sequence}
			if _, ok := reads[key]; ok {
				return bad("read_reused")
			}
			if report.Reads >= limits.Runs {
				return unavailable("read_limit")
			}
			if uint64(len(s.Source.Frames)) > limits.Records {
				return unavailable("frame_limit")
			}
			reads[key] = restoreRoots{s, writer, position}
			report.Reads++
		case *RestoreRec:
			if !charge(uint64(size(Record{Body: s}))) {
				return unavailable("byte_limit")
			}
			if !validRestoreRec(s) {
				return bad("invalid_restore_shape")
			}
			if s.Unavailable != "" {
				return unavailable("restore_" + s.Unavailable)
			}
			root, ok := reads[s.Read]
			if !ok {
				return unavailable("original_read_missing")
			}
			if root.writer != writer || root.index >= position || usedReads[s.Read] {
				return bad("original_read_owner_or_order_changed")
			}
			usedReads[s.Read] = true
			key := coreSourceRunKey{writer, s.EngineRun}
			if seen[key] {
				return bad("restore_engine_reused")
			}
			seen[key] = true
			if report.Runs >= limits.Runs {
				return unavailable("run_limit")
			}
			report.Runs++
			if s.PlanFailed != 0 || s.Installed == 0 {
				return unavailable("failed_restore_not_supported")
			}
			for _, f := range root.read.Source.Frames {
				if f.Bytes[8] == 2 {
					return unavailable("next_height_not_supported")
				}
			}
			plan, err := independentRestorePlan(root.read, s.From)
			if err != nil {
				return bad("original_boundary_or_input_invalid")
			}
			if plan.head != nil && plan.head.Number.AddUint64(1).String() != s.From {
				return bad("boundary_height_changed")
			}
			indices := make([]uint64, len(plan.steps))
			for i, in := range plan.steps {
				indices[i] = in.index
			}
			if s.Boundary != plan.boundary || !slices.Equal(s.Inputs, indices) {
				return bad("actual_restore_selection_changed")
			}
			if plan.boundary == 0 || len(plan.steps) == 0 {
				if len(s.Attempts) != 0 || s.Replayed != 0 {
					return bad("unexpected_restore_attempt")
				}
				continue
			}
			if len(s.Attempts) == 0 {
				return unavailable("restore_attempt_missing")
			}
			w, ok := configs[writer]
			if !ok || w.backlog > math.MaxInt {
				return unavailable("core_configuration_missing")
			}
			cfg, err := types.ParseChainConfig(w.config)
			if err != nil || cfg.CheckTransitions() != nil || cfg.CheckProposerPolicy() != nil {
				return unavailable("unsupported_core_configuration")
			}
			count := len(plan.steps)
			var core *consensus.State
			var expected RestoreAttempt
			var restoredTimers [4]*consensus.ArmTimer
			for i, attempt := range s.Attempts {
				if i > 0 {
					if expected.Failed == 0 || expected.LastPartial == 0 || count == 0 {
						return bad("unexpected_restore_retry")
					}
					count--
				}
				if uint64(count)+1 > limits.Steps-steps {
					return unavailable("step_limit")
				}
				for _, step := range plan.steps[:count] {
					if uint64(len(step.env)) > limits.Environments-environments {
						return unavailable("environment_limit")
					}
					environments += uint64(len(step.env))
				}
				var outCount uint64
				restoredTimers = [4]*consensus.ArmTimer{}
				core, expected, outCount, err = independentRestoreAttempt(plan, count, consensus.Options{Config: cfg, Self: w.self, Improvements: consensus.ImprovementSet(w.improvements), BacklogLimit: int(w.backlog)}, limits.Outputs-outputs, func(outs []consensus.Output) {
					for _, out := range outs {
						switch o := out.(type) {
						case consensus.ArmTimer:
							a := o
							restoredTimers[o.Kind] = &a
						case consensus.CancelTimers:
							for _, k := range o.Kinds {
								restoredTimers[k] = nil
							}
						}
					}
				})
				if errors.Is(err, errRestoreOutputLimit) {
					return unavailable("output_limit")
				}
				if err != nil {
					return bad("original_replay_input_invalid")
				}
				outputs += outCount
				steps += uint64(count) + 1
				if !sameRestoreAttempt(attempt, expected) {
					return bad("actual_restore_attempt_changed")
				}
				report.Attempts++
				report.Inputs += expected.Fed
			}
			if expected.Failed != 0 {
				return unavailable("failed_restore_not_supported")
			}
			if s.Replayed != 1 || s.Steps != expected.Steps || s.Snapshot != expected.Snapshot || !slices.Equal(s.Generations, expected.Generations) || !sameRestoreOwn(s.Own, expected.Own) {
				return bad("installed_restore_state_changed")
			}
			if s.Steps == math.MaxUint64 {
				return unavailable("step_exhausted")
			}
			var ownFrames []int
			for _, step := range plan.steps[:count] {
				ownFrames = append(ownFrames, step.ownFrames...)
			}
			seeds[key] = restoredCoreSeed{model: &coreSourceRun{state: core, next: s.Steps + 1, head: bytes.Clone(planHeadBytes(plan))}, ready: position, config: w, timers: restoredTimers, own: expected.Own, read: root.read, readIndex: root.index, installed: s, ownFrames: ownFrames}
		}
	}
	if report.Runs == 0 {
		return unavailable("no_restore_sources")
	}
	// ReadAllObserved also supplies independent read witnesses, including an
	// optional read after WAL Close. Only a RestoreRec assigns a read to an
	// installation. Never infer that an unreferenced read performed a restore.
	for ref := range reads { //wbft:unordered only the count of unreferenced reads is accumulated
		if !usedReads[ref] {
			report.UnreferencedReads++
		}
	}
	// A retained live engine still requires its actual installation record.
	// Extra read witnesses cannot hide a missing cold or replayed result.
	writer = ""
	for _, record := range records {
		switch source := record.Body.(type) {
		case *SegmentRec:
			writer = source.Run
		case *CoreStepRec:
			if !seen[coreSourceRunKey{writer, source.EngineRun}] {
				return unavailable("restore_result_missing")
			}
		}
	}
	report.Status = "consistent"
	return report, seeds, nil
}

func planHeadBytes(p *restorePlan) []byte { b, _ := codec.EncodeHeader(p.head); return b }

func independentRestorePlan(root *WALReadRec, from string) (*restorePlan, error) {
	p := new(restorePlan)
	start := -1
	var boundary restoreBoundary
	for i, f := range root.Source.Frames {
		if f.Bytes[8] != 1 || (f.Bytes[9] != 1 && f.Bytes[9] != 6) {
			continue
		}
		var b restoreBoundary
		if err := rlp.DecodeStrict(f.Bytes[10:], &b); err != nil {
			return nil, err
		}
		if b.From == nil || b.From.Sign() < 0 || len(b.Gens) != 3 && len(b.Gens) != 4 || b.HasSet > 1 || b.Replayed > 1 {
			return nil, ErrRestoreSource
		}
		if b.From.String() == from && (f.Bytes[9] == 6 || b.Replayed == 0) {
			start, boundary = i, b
		}
	}
	if start < 0 {
		return p, nil
	}
	p.boundary = uint64(start) + 1
	var err error
	p.head, err = codec.DecodeHeader(boundary.Head)
	if err != nil {
		return nil, err
	}
	p.gens = slices.Clone(boundary.Gens)
	if boundary.HasSet == 1 {
		p.vs, err = validator.NewSet(boundary.Addrs, boundary.Keys, types.ProposerPolicy{ID: boundary.Policy})
		if err != nil {
			return nil, err
		}
	}
	for i := start + 1; i < len(root.Source.Frames); i++ {
		f := root.Source.Frames[i]
		if f.Bytes[8] != 1 {
			continue
		}
		switch f.Bytes[9] {
		case 1:
			var b restoreBoundary
			if rlp.DecodeStrict(f.Bytes[10:], &b) != nil || b.Replayed != 1 || b.From == nil || b.From.String() != from {
				return p, nil
			}
		case 6:
			return p, nil
		case 2:
			var in restoreInput
			if err := rlp.DecodeStrict(f.Bytes[10:], &in); err != nil {
				return nil, err
			}
			if in.Kind == inputlog.KindNewHead {
				decoded, e := inputlog.Decode(in.Kind, in.Body, nil)
				if e == nil {
					h := decoded.(consensus.NewHead).Header
					if h != nil && h.Number.Big().Cmp(boundary.From) >= 0 {
						return p, nil
					}
				}
			}
			p.steps = append(p.steps, restoreStep{index: uint64(i) + 1, in: in})
		case 3:
			if len(p.steps) > 0 {
				p.steps[len(p.steps)-1].env = append(p.steps[len(p.steps)-1].env, f.Bytes[10:])
			}
		case 4:
			if len(p.steps) > 0 {
				var o restoreOwnWire
				if err := rlp.DecodeStrict(f.Bytes[10:], &o); err != nil {
					return nil, err
				}
				p.steps[len(p.steps)-1].own = append(p.steps[len(p.steps)-1].own, o)
				p.steps[len(p.steps)-1].ownFrames = append(p.steps[len(p.steps)-1].ownFrames, i)
			}
		}
	}
	return p, nil
}

type restoreStartEnv struct {
	*coreSourceEnv
	vs *validator.Set
}

func (e *restoreStartEnv) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	if e.vs == nil {
		return nil, ErrRestoreSource
	}
	return e.vs, nil
}
func (e *restoreStartEnv) ValidateProposal(*types.Block) (time.Duration, error) {
	return 0, ErrRestoreSource
}
func (e *restoreStartEnv) IsBadBlock(types.Hash) bool { return false }

var errRestoreOutputLimit = errors.New("restore output limit")

func independentRestoreAttempt(p *restorePlan, count int, options consensus.Options, outputLimit uint64, capture func([]consensus.Output)) (*consensus.State, RestoreAttempt, uint64, error) {
	core := consensus.NewState(options)
	a := RestoreAttempt{Inputs: uint64(count), Generations: make([]uint64, 4), Timers: make([][]byte, 4)}
	own := map[uint64][]byte{}
	var outputCount uint64
	finish := func() (*consensus.State, RestoreAttempt, uint64, error) {
		var err error
		a.Snapshot, err = RestoreSnapshotDigest(core.Snapshot())
		for code, payload := range own {
			a.Own = append(a.Own, RestoreOwn{code, bytes.Clone(payload)})
		}
		slices.SortFunc(a.Own, func(a, b RestoreOwn) int {
			if a.Code < b.Code {
				return -1
			}
			if a.Code > b.Code {
				return 1
			}
			return 0
		})
		return core, a, outputCount, err
	}
	track := func(outs []consensus.Output) error {
		if uint64(len(outs)) > outputLimit-outputCount {
			return errRestoreOutputLimit
		}
		outputCount += uint64(len(outs))
		for _, out := range outs {
			switch o := out.(type) {
			case consensus.ArmTimer:
				if uint64(o.Kind) >= 4 {
					return ErrRestoreSource
				}
				encoded, err := inputlog.EncodeOutputs([]consensus.Output{o})
				if err != nil {
					return err
				}
				a.Timers[o.Kind] = encoded
				a.Generations[o.Kind] = o.Gen
			case consensus.CancelTimers:
				for _, k := range o.Kinds {
					if uint64(k) >= 4 {
						return ErrRestoreSource
					}
					a.Timers[k] = nil
				}
			}
		}
		if capture != nil {
			capture(outs)
		}
		return nil
	}
	if err := core.RestoreTimerGenerations(p.gens); err != nil {
		a.Failed = 1
		return finish()
	}
	outs := core.Step(&restoreStartEnv{&coreSourceEnv{head: p.head}, p.vs}, consensus.Start{})
	if err := track(outs); err != nil {
		return core, a, outputCount, err
	}
	a.Steps = 1
	for i, step := range p.steps[:count] {
		in, err := inputlog.Decode(step.in.Kind, step.in.Body, nil)
		if err != nil {
			a.Failed = 1
			return finish()
		}
		env := &coreSourceEnv{head: p.head}
		for _, b := range step.env {
			c, err := inputlog.DecodeEnv(b)
			if err != nil {
				a.Failed = 1
				return finish()
			}
			env.answers = append(env.answers, c)
		}
		outs = core.Step(env, in)
		a.Fed++
		if env.err != nil {
			a.Failed = 1
			if i == count-1 {
				a.LastPartial = 1
			}
			return finish()
		}
		if len(env.answers) != 0 {
			a.Failed = 1
			return finish()
		}
		if !independentRestoreOwn(outs, step.own, own) {
			a.Failed = 1
			if i == count-1 {
				a.LastPartial = 1
			}
			return finish()
		}
		if err := track(outs); err != nil {
			return core, a, outputCount, err
		}
		a.Steps++
	}
	return finish()
}

func independentRestoreOwn(outs []consensus.Output, records []restoreOwnWire, last map[uint64][]byte) bool {
	i := 0
	for _, out := range outs {
		b, ok := out.(consensus.Broadcast)
		if !ok {
			continue
		}
		if i >= len(records) {
			return false
		}
		r := records[i]
		i++
		if b.Msg == nil || uint64(b.Msg.Code) != r.Code {
			return false
		}
		if r.Refused == 1 {
			if r.Seq == nil || r.Round == nil || b.Msg.View.Sequence.Big().Cmp(r.Seq) != 0 || b.Msg.View.Round.Big().Cmp(r.Round) != 0 {
				return false
			}
			continue
		}
		m, err := codec.DecodeMessage(codec.Code(r.Code), r.Payload)
		if err != nil {
			return false
		}
		want, err := codec.SigningPayload(m, false, nil)
		if err != nil {
			return false
		}
		copy := *b.Msg
		copy.Seal = m.Seal
		got, err := codec.SigningPayload(&copy, false, nil)
		if err != nil || !bytes.Equal(got, want) {
			return false
		}
		last[r.Code] = r.Payload
	}
	return i == len(records)
}
func sameRestoreAttempt(a, b RestoreAttempt) bool {
	x, e := rlp.Encode(&a)
	if e != nil {
		return false
	}
	y, e := rlp.Encode(&b)
	return e == nil && bytes.Equal(x, y)
}

// CheckRestoredCoreSources is the explicit inspection path for verified restore
// seeds. The ordinary CheckCoreStepSources still rejects restored prefixes.
func CheckRestoredCoreSources(records []Record, limits CoreSourceLimits) (RestoreCheck, CoreSourceCheck, error) {
	restore, seeds, err := reconstructRestoreSources(records, limits)
	if err != nil || restore.Status != "consistent" {
		return restore, CoreSourceCheck{Status: "unavailable", Reason: "restore_not_reconstructed"}, err
	}
	terminals := map[coreSourceRunKey]*RestoreRec{}
	writer := ""
	for _, rec := range records {
		switch r := rec.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *RestoreRec:
			terminals[coreSourceRunKey{writer, r.EngineRun}] = r
		}
	}
	seen := map[coreSourceRunKey]bool{}
	fresh := map[coreSourceRunKey]bool{}
	freshGenerations := map[coreSourceRunKey][]uint64{}
	freshBroadcast := map[coreSourceRunKey]bool{}
	contradiction := ""
	core, _, err := inspectCoreSourceStatesRestored(records, limits, func(writer string, s *CoreStepRec, outputs []consensus.Output) {
		if s.Step != 1 || s.ReplayedPrefix {
			return
		}
		gens := make([]uint64, 4)
		for _, out := range outputs {
			switch o := out.(type) {
			case consensus.ArmTimer:
				if uint64(o.Kind) >= 4 {
					contradiction = "fresh_timer_kind_changed"
					return
				}
				gens[o.Kind] = o.Gen
			case consensus.Broadcast:
				// Signing and accepted outbound ownership need separate evidence;
				// never synthesize a signed own payload from recorded output bytes.
				freshBroadcast[coreSourceRunKey{writer, s.EngineRun}] = true
			}
		}
		freshGenerations[coreSourceRunKey{writer, s.EngineRun}] = gens
	}, func(writer string, s *CoreStepRec, snapshot *consensus.Snapshot) {
		key := coreSourceRunKey{writer, s.EngineRun}
		seen[key] = true
		if s.Step != 1 || s.ReplayedPrefix {
			return
		}
		terminal, ok := terminals[key]
		if !ok {
			return
		}
		head, e := codec.DecodeHeader(s.Head)
		if e != nil || head.Number.AddUint64(1).String() != terminal.From {
			contradiction = "fresh_restore_height_changed"
			return
		}
		digest, e := RestoreSnapshotDigest(snapshot)
		if e != nil || terminal.Replayed != 0 || terminal.Steps != 1 || terminal.Snapshot != digest {
			contradiction = "fresh_installation_changed"
			return
		}
		fresh[key] = true
	}, seeds)
	if err != nil || core.Status != "consistent" {
		return restore, core, err
	}
	if contradiction != "" {
		core.Status, core.Reason = "inconsistent", contradiction
		return restore, core, fmt.Errorf("%w: %s", ErrRestoreSource, contradiction)
	}
	for key := range seeds {
		if !seen[key] {
			core.Status, core.Reason = "unavailable", "restored_live_step_missing"
			return restore, core, nil
		}
	}
	for key, t := range terminals {
		if t.Replayed == 0 && !fresh[key] {
			core.Status, core.Reason = "unavailable", "fresh_start_source_missing"
			return restore, core, nil
		}
		if t.Replayed == 0 && !slices.Equal(t.Generations, freshGenerations[key]) {
			core.Status, core.Reason = "inconsistent", "fresh_generations_changed"
			return restore, core, fmt.Errorf("%w: %s", ErrRestoreSource, core.Reason)
		}
		if t.Replayed == 0 && !freshBroadcast[key] && len(t.Own) != 0 {
			core.Status, core.Reason = "inconsistent", "fresh_own_changed"
			return restore, core, fmt.Errorf("%w: %s", ErrRestoreSource, core.Reason)
		}
	}
	if len(freshBroadcast) > 0 {
		core.Status, core.Reason = "unavailable", "fresh_broadcast_installation_not_supported"
	}
	return restore, core, nil
}

func sameRestoreOwn(a, b []RestoreOwn) bool {
	x, e := rlp.Encode(a)
	if e != nil {
		return false
	}
	y, e := rlp.Encode(b)
	return e == nil && bytes.Equal(x, y)
}
