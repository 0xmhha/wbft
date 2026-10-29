package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

const (
	validatorStartFormat      uint8  = 5
	validatorStartVersion     uint64 = 1
	walValidatorIntent        uint8  = 10
	walValidatorComplete      uint8  = 12
	walValidatorHalt          uint8  = 13
	validatorHistoryHaltBytes uint64 = 1024
	validatorHistoryHaltCount uint64 = 1
	validatorControlSeed      uint64 = 1
	validatorControlResume    uint64 = 2
	validatorControlIntent    uint64 = 3
	validatorControlComplete  uint64 = 4
	validatorControlHalt      uint64 = 5
	validatorHaltLimit        uint64 = 1
	validatorHaltFailure      uint64 = 2
)

var errValidatorHistoryProfile = errors.New("runner: validator-start WAL requires a complete matching profile")
var errValidatorHistoryHalted = errors.New("runner: validator-start history was terminally halted")

type validatorHistoryChainOptions struct {
	Base            types.Params
	Transitions     []types.Transition
	Init            types.GenesisInit
	ChainID         *string
	RuleActivations map[types.RuleName]string
	RulesDigest     types.Hash
}

type validatorHistoryOptions struct {
	Version      uint64
	Self         types.Address
	Improvements uint64
	Backlog      int64
	Chain        *validatorHistoryChainOptions
	Retry        *consensus.RoundChangeRetryOptions
	Next         *NextHeightLimits
	History      ValidatorHistoryLimits
}

// validatorHistoryOptionsBytes projects every effective core configuration
// component explicitly. Config's private base, transitions and rules cannot
// be frozen by directly marshalling its exported fields alone.
func validatorHistoryOptionsBytes(cfg Config) ([]byte, error) {
	if !cfg.ReplayWAL || !cfg.Core.Improvements.Has(consensus.DeferValidatorStart) {
		return nil, errValidatorHistoryProfile
	}
	if err := freezeValidatorHistoryConfig(&cfg, nil); err != nil {
		return nil, err
	}
	o := validatorHistoryOptions{Version: validatorStartVersion, Self: cfg.Core.Self,
		Improvements: uint64(cfg.Core.Improvements), Backlog: int64(max(cfg.Core.BacklogLimit, consensus.MinBacklogLimit)),
		Retry: cfg.Core.RoundChangeRetry.Copy(), History: *cfg.ValidatorHistory}
	if cfg.NextHeight != nil {
		next := *cfg.NextHeight
		if next.Entries == 0 || next.Bytes == 0 || next.PerPeer == 0 || next.PerSource == 0 {
			return nil, errValidatorHistoryProfile
		}
		o.Next = &next
	}
	if c := cfg.Core.Config; c != nil {
		o.Chain = &validatorHistoryChainOptions{Base: c.Base(), Transitions: c.Transitions(), Init: c.Init,
			RuleActivations: c.RuleActivations(), RulesDigest: c.RulesDigest()}
		if c.ChainID != nil {
			id := c.ChainID.String()
			o.Chain.ChainID = &id
		}
	}
	return json.Marshal(o)
}

type validatorHistoryEnvironment struct {
	Bytes []byte
	Keys  []uint64
}

func validatorHistoryWitness(call inputlog.EnvCall) (validatorHistoryEnvironment, error) {
	observed, err := observeCoreEnvironment(call)
	if err != nil {
		return validatorHistoryEnvironment{}, err
	}
	w := validatorHistoryEnvironment{Bytes: observed.Bytes, Keys: make([]uint64, len(observed.ValidatorKeyPresent))}
	for i, present := range observed.ValidatorKeyPresent {
		if present {
			w.Keys[i] = 1
		}
	}
	return w, nil
}

func (w validatorHistoryEnvironment) call() (inputlog.EnvCall, error) {
	observed := journal.CoreEnvObservation{Bytes: bytes.Clone(w.Bytes), ValidatorKeyPresent: make([]bool, len(w.Keys))}
	for i, present := range w.Keys {
		if present > 1 {
			return inputlog.EnvCall{}, errValidatorHistoryProfile
		}
		observed.ValidatorKeyPresent[i] = present == 1
	}
	call, err := journal.DecodeCoreEnvironment(observed)
	if err != nil || call.Kind == inputlog.EnvValidatorsAt && call.Validators != nil && call.Err != "" {
		return inputlog.EnvCall{}, errValidatorHistoryProfile
	}
	return call, nil
}

type validatorHistoryView struct {
	Adopted uint64
	Seq     *big.Int
	Round   *big.Int
}

func validatorHistoryAdoption(core *consensus.State) validatorHistoryView {
	v, adopted := core.AdoptedView()
	out := validatorHistoryView{Seq: v.Sequence.Big(), Round: v.Round.Big()}
	if adopted {
		out.Adopted = 1
	}
	return out
}

func (v validatorHistoryView) value() (types.View, error) {
	n, err := types.HeightFromBig(v.Seq)
	if err != nil {
		return types.View{}, errValidatorHistoryProfile
	}
	r, err := types.RoundFromBig(v.Round)
	if err != nil || v.Adopted > 1 || v.Adopted == 0 && (!n.IsZero() || !r.IsZero()) || v.Adopted == 1 && n.IsZero() {
		return types.View{}, errValidatorHistoryProfile
	}
	return types.View{Sequence: n, Round: r}, nil
}

type validatorHistoryWait struct {
	Target, Round *big.Int
	Parent        types.Hash
	Cause, Reason string
	Gen, Live, RC uint64
}

func validatorHistoryWaitBytes(wait *consensus.ValidatorStartWait) ([]byte, error) {
	if wait == nil {
		return []byte{}, nil
	}
	w := validatorHistoryWait{Target: wait.Target.Big(), Round: wait.RequestedRound.Big(), Parent: wait.Parent,
		Cause: wait.Cause, Reason: wait.Reason, Gen: wait.Generation}
	if wait.Live {
		w.Live = 1
	}
	if wait.RoundChangeOnResume {
		w.RC = 1
	}
	encoded, err := rlp.Encode(w)
	if err != nil {
		return nil, err
	}
	if _, err := decodeValidatorHistoryWait(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func decodeValidatorHistoryWait(encoded []byte) (*consensus.ValidatorStartWait, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var w validatorHistoryWait
	if rlp.DecodeStrict(encoded, &w) != nil || w.Gen == 0 || w.Live > 1 || w.RC > 1 {
		return nil, errValidatorHistoryProfile
	}
	target, err := types.HeightFromBig(w.Target)
	if err != nil || target.IsZero() {
		return nil, errValidatorHistoryProfile
	}
	round, err := types.RoundFromBig(w.Round)
	if err != nil {
		return nil, errValidatorHistoryProfile
	}
	switch w.Cause {
	case event.CauseStart, event.CauseNewHead:
		if w.RC != 0 {
			return nil, errValidatorHistoryProfile
		}
	case event.CauseTimeout, event.CauseFPlusOne, event.CauseFinalizeFail:
	default:
		return nil, errValidatorHistoryProfile
	}
	switch w.Reason {
	case "validator_set_unavailable":
		if w.Live != 1 {
			return nil, errValidatorHistoryProfile
		}
	case "validator_start_generation_exhausted":
		if w.Live != 0 || w.Gen != math.MaxUint64 {
			return nil, errValidatorHistoryProfile
		}
	default:
		return nil, errValidatorHistoryProfile
	}
	return &consensus.ValidatorStartWait{Target: target, Parent: w.Parent, RequestedRound: round, Cause: w.Cause,
		Reason: w.Reason, Generation: w.Gen, Live: w.Live == 1, RoundChangeOnResume: w.RC == 1}, nil
}

// validatorHistoryControl supplements original input/Env/own/commit records.
// Shape validation is separate from full-prefix execution and configuration
// validation; in particular a suspended target can differ from Env.Head.
type validatorHistoryControl struct {
	Version, Mode         uint64
	Options               []byte
	Anchor, Prefix        types.Hash
	Records, Bytes        uint64
	Head                  []byte
	InputRecord           uint64
	InputKind             string
	InputHash             types.Hash
	Environment           []validatorHistoryEnvironment
	Before, After         []uint64
	BeforeView, AfterView validatorHistoryView
	Wait                  []byte
	Outputs               types.Hash
	InnerFormat           uint64
	Inner                 []byte
	HaltReason            uint64
}

func (c validatorHistoryControl) validate(kind uint8) error {
	if c.Version != validatorStartVersion || c.Records > math.MaxInt64 || c.Bytes > math.MaxInt64 {
		return errValidatorHistoryProfile
	}
	before, err := c.BeforeView.value()
	if err != nil {
		return err
	}
	after, err := c.AfterView.value()
	if err != nil {
		return err
	}
	if c.Mode == validatorControlHalt {
		if kind != walValidatorHalt || c.HaltReason != validatorHaltLimit && c.HaltReason != validatorHaltFailure || c.Anchor == (types.Hash{}) || c.Prefix == (types.Hash{}) || c.Records == 0 || c.Bytes == 0 ||
			len(c.Options)+len(c.Head)+len(c.Environment)+len(c.Before)+len(c.After)+len(c.Wait)+len(c.Inner) != 0 ||
			c.BeforeView.Adopted != 0 || c.AfterView.Adopted != 0 || c.InputRecord != 0 || c.InputKind != "" ||
			c.InputHash != (types.Hash{}) || c.Outputs != (types.Hash{}) || c.InnerFormat != 0 {
			return errValidatorHistoryProfile
		}
		return nil
	}
	if c.HaltReason != 0 {
		return errValidatorHistoryProfile
	}
	if len(c.Before) != 5 || len(c.After) != 5 || len(c.Head) == 0 {
		return errValidatorHistoryProfile
	}
	if _, err := codec.DecodeHeader(c.Head); err != nil {
		return errValidatorHistoryProfile
	}
	wait, err := decodeValidatorHistoryWait(c.Wait)
	if err != nil || wait == nil && c.AfterView.Adopted == 0 || wait != nil && wait.Generation != c.After[4] {
		return errValidatorHistoryProfile
	}
	for _, witness := range c.Environment {
		if _, err := witness.call(); err != nil {
			return err
		}
	}
	switch c.Mode {
	case validatorControlSeed:
		if kind != walRunStart || len(c.Options) == 0 || c.Anchor != (types.Hash{}) || c.Prefix != (types.Hash{}) ||
			c.Records != 0 || c.Bytes != 0 || c.InputRecord != 0 || c.InputKind != inputlog.KindStart || c.BeforeView.Adopted != 0 ||
			!slices.Equal(c.Before, []uint64{0, 0, 0, 0, 0}) {
			return errValidatorHistoryProfile
		}
	case validatorControlResume:
		if kind != walRunStart || len(c.Options)+len(c.Environment) != 0 || c.InputRecord != 0 || c.InputKind != "" ||
			c.InputHash != (types.Hash{}) || c.Outputs != (types.Hash{}) || !slices.Equal(c.Before, c.After) ||
			c.BeforeView.Adopted != c.AfterView.Adopted || before.Cmp(after) != 0 {
			return errValidatorHistoryProfile
		}
	case validatorControlIntent, validatorControlComplete:
		if len(c.Options) != 0 || c.InputRecord == 0 || c.InputKind == "" || c.InputKind == inputlog.KindStart || c.InputKind == inputlog.KindStop {
			return errValidatorHistoryProfile
		}
		if c.Mode == validatorControlIntent {
			if kind != walValidatorIntent || c.InnerFormat != 0 || len(c.Inner) != 0 {
				return errValidatorHistoryProfile
			}
		} else {
			height := c.BeforeView.Adopted == 1 && c.AfterView.Adopted == 1 && after.Sequence.Cmp(before.Sequence) > 0
			if len(c.Environment) != 0 || height && kind != walEndHeight || !height && kind != walValidatorComplete {
				return errValidatorHistoryProfile
			}
		}
	default:
		return errValidatorHistoryProfile
	}
	if c.Mode != validatorControlSeed && (c.Anchor == (types.Hash{}) || c.Prefix == (types.Hash{}) || c.Records == 0 || c.Bytes == 0) {
		return errValidatorHistoryProfile
	}
	if c.InnerFormat == 0 {
		if len(c.Inner) != 0 {
			return errValidatorHistoryProfile
		}
	} else {
		if wait != nil || kind != walRunStart && kind != walEndHeight || c.InnerFormat > uint64(roundChangeRetryFormat) {
			return errValidatorHistoryProfile
		}
		if _, _, err := decodeRunnerBoundary(wal.Record{Format: uint8(c.InnerFormat), Kind: kind, Body: c.Inner}); err != nil {
			return errValidatorHistoryProfile
		}
	}
	return nil
}

func encodeValidatorHistoryControl(kind uint8, control validatorHistoryControl) (wal.Record, error) {
	if err := control.validate(kind); err != nil {
		return wal.Record{}, err
	}
	body, err := rlp.Encode(control)
	if err != nil {
		return wal.Record{}, err
	}
	record := wal.Record{Format: validatorStartFormat, Kind: kind, Body: body}
	if control.Mode == validatorControlHalt && uint64(len(body))+validatorHistoryFrameOverhead > validatorHistoryHaltBytes {
		return wal.Record{}, errValidatorHistoryProfile
	}
	return record, nil
}

func decodeValidatorHistoryControl(record wal.Record) (validatorHistoryControl, error) {
	var control validatorHistoryControl
	if record.Format != validatorStartFormat || rlp.DecodeStrict(record.Body, &control) != nil || control.validate(record.Kind) != nil {
		return control, errValidatorHistoryProfile
	}
	canonical, err := encodeValidatorHistoryControl(record.Kind, control)
	if err != nil || !bytes.Equal(canonical.Body, record.Body) {
		return control, errValidatorHistoryProfile
	}
	return control, nil
}

func validatorHistoryRecordHash(record wal.Record) (types.Hash, error) {
	frame, err := wal.Encode(record)
	if err != nil {
		return types.Hash{}, err
	}
	return sha256.Sum256(frame), nil
}

// validatorHistoryInputHash binds the canonical semantic input. A deferred
// input keeps its original physical record separately in the prefix hash.
func validatorHistoryInputHash(kind string, body []byte) (types.Hash, error) {
	return validatorHistoryRecordHash(encodeInput(kind, body))
}

func validatorHistoryPrefix(previous types.Hash, record wal.Record) (types.Hash, error) {
	frame, err := wal.Encode(record)
	if err != nil {
		return types.Hash{}, err
	}
	h := sha256.New()
	_, _ = h.Write(previous[:])
	_, _ = h.Write(frame)
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}
