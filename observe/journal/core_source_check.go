package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// CoreSourceLimits bound transcript inspection and indexes. Bytes counts
// inspected payload spans, not WAL decoding allocations or process heap.
type CoreSourceLimits struct{ Records, Runs, Steps, Environments, Outputs, Bytes uint64 }

// CoreSourceCheck is conditional execution consistency on recorded inputs and
// environment answers. Internal scheduling, application execution, network,
// cache mutations and WAL restoration are not validated by this comparison.
type CoreSourceCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	ScheduleStatus string `json:"schedule_status"`
	Runs           uint64 `json:"runs,string"`
	Steps          uint64 `json:"steps,string"`
	Outputs        uint64 `json:"outputs,string"`
	Accepted       uint64 `json:"accepted_outputs,string"`
}

var ErrCoreSource = errors.New("journal: inconsistent core execution source")

type coreSourceRunKey struct {
	writer string
	engine uint64
}
type coreSourceRun struct {
	state *consensus.State
	next  uint64
	head  []byte
}
type coreSourceWriter struct {
	retry                 RoundChangeRetryOptions
	proposerProfile       string
	config                []byte
	self                  types.Address
	improvements, backlog uint64
}
type coreSourceAccepted struct {
	writer                      string
	engine, step, output        uint64
	peer                        types.Address
	code                        uint64
	key                         types.Hash
	via                         string
	input                       transportCoreInput
	before                      transport.ValidationContext
	beforeKnown                 bool
	origin                      transport.ReceiveOrigin
	receiveLedgerRun            string
	receiveLedger, receiveScope uint64
}
type transportCoreInput struct {
	identity transport.WriteIdentity
	present  bool
}

// CheckCoreStepSources executes a fresh core from separate KindCoreStep values.
// No observed cache/receive/write mutation or recorded output is injected into
// that core. Existing functional RunTrace/cache-profile guards remain separate.
func CheckCoreStepSources(records []Record, limits CoreSourceLimits) (CoreSourceCheck, error) {
	report, _, err := reconstructCoreSources(records, limits)
	return report, err
}

func reconstructCoreSources(records []Record, limits CoreSourceLimits) (CoreSourceCheck, []coreSourceAccepted, error) {
	return inspectCoreSourceOutputs(records, limits, nil)
}

// capture sees only outputs independently recomputed and already compared with
// retained sources. It is private inspection code, never a runner callback.
func inspectCoreSourceOutputs(records []Record, limits CoreSourceLimits, capture func(string, *CoreStepRec, []consensus.Output)) (CoreSourceCheck, []coreSourceAccepted, error) {
	return inspectCoreSourceStates(records, limits, capture, nil)
}

// Snapshot consumers receive only independently executed, source-checked states.
func inspectCoreSourceStates(records []Record, limits CoreSourceLimits, capture func(string, *CoreStepRec, []consensus.Output), snapshots func(string, *CoreStepRec, *consensus.Snapshot)) (CoreSourceCheck, []coreSourceAccepted, error) {
	return inspectCoreSourceStatesRestored(records, limits, capture, snapshots, nil)
}

func inspectCoreSourceStatesRestored(records []Record, limits CoreSourceLimits, capture func(string, *CoreStepRec, []consensus.Output), snapshots func(string, *CoreStepRec, *consensus.Snapshot), seeds map[coreSourceRunKey]restoredCoreSeed) (CoreSourceCheck, []coreSourceAccepted, error) {
	return inspectCoreSourceProfile(records, limits, capture, snapshots, seeds, false)
}

// The private failure inspector reconstructs the same original core inputs.
// Its separate cache/inbox proof must succeed before it reports consistency.
// Ordinary callers retain the unsupported-profile guard.
func inspectCoreSourceProfile(records []Record, limits CoreSourceLimits, capture func(string, *CoreStepRec, []consensus.Output), snapshots func(string, *CoreStepRec, *consensus.Snapshot), seeds map[coreSourceRunKey]restoredCoreSeed, failures bool) (CoreSourceCheck, []coreSourceAccepted, error) {
	report := CoreSourceCheck{Status: "unavailable", Scope: "core_execution_on_recorded_inputs", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable"}
	unavailable := func(reason string) (CoreSourceCheck, []coreSourceAccepted, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil, nil
	}
	inconsistent := func(reason string) (CoreSourceCheck, []coreSourceAccepted, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, nil, fmt.Errorf("%w: %s", ErrCoreSource, reason)
	}
	if limits.Records == 0 || limits.Runs == 0 || limits.Steps == 0 || limits.Environments == 0 || limits.Outputs == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	writers := map[string]coreSourceWriter{}
	runs := map[coreSourceRunKey]*coreSourceRun{}
	var accepted []coreSourceAccepted
	writer := ""
	var environments, usedBytes uint64
	charge := func(n int) bool {
		if uint64(n) > limits.Bytes-usedBytes {
			return false
		}
		usedBytes += uint64(n)
		return true
	}
	for position, record := range records {
		switch s := record.Body.(type) {
		case *SegmentRec:
			writer = s.Run
			if writer == "" {
				return unavailable("writer_missing")
			}
			if !charge(len(s.Core.ChainConfig)) {
				return unavailable("source_byte_limit")
			}
			if len(s.Core.ChainConfig) == 0 {
				return unavailable("core_configuration_missing")
			}
			if s.Core.ReceiveFailureCache != nil {
				// Decoding the declaration does not make the existing source
				// inspector understand cached failures or their inbox positions.
				if !failures {
					return unavailable("receive_failure_source_profile_unavailable")
				}
				if s.Core.validateReceiveFailureHeader() != nil {
					return unavailable("unsupported_receive_failure_declaration")
				}
			}
			if s.Core.BacklogLimit > math.MaxInt {
				return unavailable("core_backlog_range")
			}
			w := coreSourceWriter{config: bytes.Clone(s.Core.ChainConfig), self: s.Core.Self, improvements: s.Core.Improvements, backlog: s.Core.BacklogLimit, proposerProfile: s.Core.ProposerPolicyProfile}
			if s.Core.RoundChangeRetry != nil {
				if s.Core.RoundChangeRetry.Validate() != nil {
					return unavailable("unsupported_retry_profile")
				}
				w.retry = *s.Core.RoundChangeRetry
			}
			if old, ok := writers[writer]; ok && (old.self != w.self || old.improvements != w.improvements || old.backlog != w.backlog || old.retry != w.retry || old.proposerProfile != w.proposerProfile || !bytes.Equal(old.config, w.config)) {
				return inconsistent("writer_configuration_changed")
			}
			writers[writer] = w
		case *ReceiveFailureCacheRec, *InboxFailureHitRec:
			if !failures {
				return unavailable("receive_failure_source_profile_unavailable")
			}
		case *GapRec:
			if s.Dropped > 0 && len(s.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, kind := range s.ByKind {
				if kind.Count > 0 && (kind.Kind == 0 || kind.Kind == uint64(KindCoreStep)) {
					return unavailable("core_source_gap")
				}
			}
		case *CoreStepRec:
			if report.Steps >= limits.Steps {
				return unavailable("step_limit")
			}
			for _, data := range [][]byte{s.Input, s.Outputs, s.Head} {
				if !charge(len(data)) {
					return unavailable("source_byte_limit")
				}
			}
			if uint64(len(s.Environment)) > limits.Environments-environments {
				return unavailable("environment_limit")
			}
			environments += uint64(len(s.Environment))
			for _, e := range s.Environment {
				if !charge(len(e.Bytes)) || !charge(len(e.ValidatorKeyPresent)) {
					return unavailable("source_byte_limit")
				}
			}
			if !validCoreStepSource(s) {
				return inconsistent("invalid_source_shape")
			}
			if s.Unavailable != "" {
				return unavailable("source_" + s.Unavailable)
			}
			if s.ReplayedPrefix {
				seed, ok := seeds[coreSourceRunKey{writer, s.EngineRun}]
				if !ok {
					return unavailable("restored_prefix_not_reconstructed")
				}
				if seed.ready >= position {
					return inconsistent("restore_source_after_live_step")
				}
			} else if _, ok := seeds[coreSourceRunKey{writer, s.EngineRun}]; ok {
				return inconsistent("restored_prefix_marker_missing")
			}
			w, ok := writers[writer]
			if !ok {
				return unavailable("core_writer_missing")
			}
			if s.CoreSelf != w.self || s.Improvements != w.improvements || s.BacklogLimit != int64(w.backlog) || s.RetryMaximumMs != w.retry.MaxIntervalMs {
				return inconsistent("actual_core_options_changed")
			}
			if len(s.Head) == 0 {
				return unavailable("actual_head_missing")
			}
			head, err := codec.DecodeHeader(s.Head)
			if err != nil {
				return inconsistent("invalid_actual_head")
			}
			in, err := inputlog.Decode(s.InputKind, s.Input, nil)
			if err != nil {
				return inconsistent("invalid_actual_input")
			}
			key := coreSourceRunKey{writer, s.EngineRun}
			model := runs[key]
			if model == nil {
				if seed, ok := seeds[key]; ok {
					if seed.config.self != w.self || seed.config.improvements != w.improvements || seed.config.backlog != w.backlog || seed.config.retry != w.retry || seed.config.proposerProfile != w.proposerProfile || !bytes.Equal(seed.config.config, w.config) {
						return inconsistent("restore_configuration_changed")
					}
					if report.Runs >= limits.Runs {
						return unavailable("run_limit")
					}
					model = seed.model
					runs[key] = model
					report.Runs++
				}
			}
			if model == nil {
				if s.Step != 1 || s.InputKind != inputlog.KindStart {
					return unavailable("core_start_missing")
				}
				if report.Runs >= limits.Runs {
					return unavailable("run_limit")
				}
				config, err := w.configuration()
				if err != nil {
					return unavailable("unsupported_core_configuration")
				}
				if err := config.CheckTransitions(); err != nil {
					return unavailable("unsupported_core_configuration")
				}
				if err := config.CheckProposerPolicy(); err != nil {
					return unavailable("unsupported_core_configuration")
				}
				options, err := w.options(config)
				if err != nil {
					return unavailable("unsupported_retry_configuration")
				}
				model = &coreSourceRun{state: consensus.NewState(options), next: 1, head: bytes.Clone(s.Head)}
				runs[key] = model
				report.Runs++
			}
			if model.next == 0 || s.Step < model.next {
				return inconsistent("core_step_repeated_or_exhausted")
			}
			if s.Step > model.next {
				return unavailable("core_step_gap")
			}
			if newHead, ok := in.(consensus.NewHead); ok {
				encoded, err := codec.EncodeHeader(newHead.Header)
				if err != nil || !bytes.Equal(encoded, s.Head) {
					return inconsistent("new_head_source_changed")
				}
				model.head = bytes.Clone(s.Head)
			} else if !bytes.Equal(model.head, s.Head) {
				return inconsistent("head_changed_without_input")
			}
			before, beforeKnown, err := coreSourceContext(model.state.Snapshot())
			if err != nil {
				return unavailable("authority_digest_unavailable")
			}
			if beforeKnown != s.BeforeKnown || before != s.Before {
				return inconsistent("before_context_changed")
			}
			env := &coreSourceEnv{head: head}
			for _, e := range s.Environment {
				call, err := DecodeCoreEnvironment(e)
				if err != nil {
					return inconsistent("environment_source_changed")
				}
				env.answers = append(env.answers, call)
			}
			outputs := model.state.Step(env, in)
			if env.err != nil || len(env.answers) != 0 {
				return inconsistent("environment_call_changed")
			}
			if uint64(len(outputs)) > limits.Outputs-report.Outputs {
				return unavailable("output_limit")
			}
			encoded, err := inputlog.EncodeOutputs(outputs)
			if err != nil {
				return unavailable("output_encoding_unavailable")
			}
			digest, err := inputlog.OutDigest(outputs)
			if err != nil {
				return unavailable("output_digest_unavailable")
			}
			if digest != s.OutDigest || !bytes.Equal(encoded, s.Outputs) {
				return inconsistent("core_outputs_changed")
			}
			afterSnapshot := model.state.Snapshot()
			after, afterKnown, err := coreSourceContext(afterSnapshot)
			if err != nil {
				return unavailable("authority_digest_unavailable")
			}
			if afterKnown != s.AfterKnown || after != s.After {
				return inconsistent("after_context_changed")
			}
			if snapshots != nil {
				snapshots(writer, s, afterSnapshot)
			}
			if capture != nil {
				capture(writer, s, outputs)
			}
			for index, out := range outputs {
				o, ok := out.(consensus.Outcome)
				if !ok || !o.Relayed || o.Via != "direct" && o.Via != "self" {
					continue
				}
				proof := coreSourceAccepted{writer: writer, engine: s.EngineRun, step: s.Step, output: uint64(index + 1), peer: o.Peer, code: uint64(o.Code), key: o.DedupKey, via: o.Via, before: before, beforeKnown: beforeKnown, origin: s.Origin}
				proof.receiveLedgerRun, proof.receiveLedger, proof.receiveScope = s.ReceiveLedgerRun, s.ReceiveLedger, s.ReceiveScopeBefore
				if m, ok := in.(consensus.Message); ok {
					proof.input = transportCoreInput{identity: transport.WriteIdentity{Peer: m.Peer, Code: uint64(m.Code), Key: codec.DedupKey(m.Payload), PayloadSHA256: sha256.Sum256(m.Payload), Session: s.Stream, SessionRun: s.StreamRun}, present: true}
				}
				accepted = append(accepted, proof)
				report.Accepted++
			}
			report.Steps++
			report.Outputs += uint64(len(outputs))
			if model.next == ^uint64(0) {
				model.next = 0
			} else {
				model.next++
			}
		}
	}
	if report.Steps == 0 {
		return unavailable("no_core_step_sources")
	}
	report.Status = "consistent"
	return report, accepted, nil
}

type coreSourceAuthorityMember struct {
	Address types.Address
	Present uint64
	Key     []byte
}

func coreSourceAuthorityDigest(set *validator.Set) (types.Hash, error) {
	if set == nil {
		return types.Hash{}, nil
	}
	w := struct {
		Domain  string
		Policy  uint64
		Members []coreSourceAuthorityMember
	}{Domain: "wbft/receive-authority/v1", Policy: set.Policy().ID, Members: make([]coreSourceAuthorityMember, set.Len())}
	for i := range set.Len() {
		m := set.At(i)
		w.Members[i] = coreSourceAuthorityMember{Address: m.Addr, Key: m.BLSPublicKey}
		if m.BLSPublicKey != nil {
			w.Members[i].Present = 1
		}
	}
	encoded, err := rlp.Encode(&w)
	if err != nil {
		return types.Hash{}, err
	}
	return sha256.Sum256(encoded), nil
}
func coreSourceContext(s *consensus.Snapshot) (transport.ValidationContext, bool, error) {
	if s == nil || !s.Running {
		return transport.ValidationContext{}, false, nil
	}
	validators, err := coreSourceAuthorityDigest(s.Validators)
	if err != nil {
		return transport.ValidationContext{}, false, err
	}
	prior, err := coreSourceAuthorityDigest(s.PriorValidators)
	if err != nil {
		return transport.ValidationContext{}, false, err
	}
	return transport.ValidationContext{Sequence: s.View.Sequence.String(), Round: s.View.Round.String(), State: s.State.String(), PriorRound: s.PriorRound.String(), Validators: validators, PriorValidators: prior, ValidatorsPresent: s.Validators != nil, PriorValidatorsPresent: s.PriorValidators != nil}, true, nil
}

type coreSourceEnv struct {
	head    *types.Header
	answers []inputlog.EnvCall
	err     error
}

func (e *coreSourceEnv) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head, Proposer: types.ProposerOf(e.head)}
}
func (e *coreSourceEnv) pop(kind uint8, key types.Hash) (inputlog.EnvCall, bool) {
	if e.err != nil || len(e.answers) == 0 {
		e.err = ErrCoreSource
		return inputlog.EnvCall{}, false
	}
	c := e.answers[0]
	if c.Kind != kind || c.Key != key {
		e.err = ErrCoreSource
		return inputlog.EnvCall{}, false
	}
	e.answers = e.answers[1:]
	return c, true
}
func (e *coreSourceEnv) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	c, ok := e.pop(inputlog.EnvValidatorsAt, parent)
	if !ok || c.Number.Cmp(n) != 0 {
		e.err = ErrCoreSource
		return nil, ErrCoreSource
	}
	if c.Validators == nil {
		return nil, fmt.Errorf("recorded authority lookup: %s", c.Err)
	}
	return c.Validators, nil
}
func (e *coreSourceEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	c, ok := e.pop(inputlog.EnvValidateProposal, codec.BlockHash(b.Header))
	if !ok {
		return 0, ErrCoreSource
	}
	return c.ProposalAnswer()
}
func (e *coreSourceEnv) ValidateRoundProposal(b *types.Block) (time.Duration, error) {
	return e.ValidateProposal(b)
}
func (e *coreSourceEnv) IsBadBlock(h types.Hash) bool {
	c, ok := e.pop(inputlog.EnvIsBadBlock, h)
	return ok && c.Bad
}
func (e *coreSourceEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	return header.CommitHeader(b, round, prepared, committed)
}

func (w coreSourceWriter) options(config *types.Config) (consensus.Options, error) {
	options := consensus.Options{Config: config, Self: w.self, Improvements: consensus.ImprovementSet(w.improvements), BacklogLimit: int(w.backlog)}
	if w.retry != (RoundChangeRetryOptions{}) {
		retry := w.retry
		var err error
		options.RoundChangeRetry, err = (CoreOptions{RoundChangeRetry: &retry}).RetryOptions(config)
		if err != nil {
			return options, err
		}
	}
	return options, nil
}

func (w coreSourceWriter) configuration() (*types.Config, error) {
	declaration := CoreOptions{ChainConfig: w.config, ProposerPolicyProfile: w.proposerProfile}
	if w.retry != (RoundChangeRetryOptions{}) {
		retry := w.retry
		declaration.RoundChangeRetry = &retry
	}
	return declaration.Configuration()
}
