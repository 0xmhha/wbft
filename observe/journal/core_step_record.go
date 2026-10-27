package journal

import (
	"bytes"
	"fmt"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// CoreEnvObservation retains actual ordered environment answers and the nil
// presence of public validator keys. It contains no process-local pointers.
type CoreEnvObservation struct {
	Bytes               []byte
	ValidatorKeyPresent []bool
}

type CoreStepMoment struct {
	Mono   int64
	WallNs int64
}

// CoreStepRec is a separate diagnostic source format, not the legacy StepRec.
// It neither enables functional cache replay nor authenticates writer/config.
// ReplayedPrefix explicitly marks a restored prefix lacking live observations.
type CoreStepRec struct {
	CoreSelf        types.Address
	Improvements    uint64
	BacklogLimit    int64
	RetryMaximumMs  uint64
	Head            []byte
	EngineRun, Step uint64
	ReplayedPrefix  bool
	Via, InputKind  string
	Input, Outputs  []byte
	OutDigest       types.Hash
	Environment     []CoreEnvObservation
	Origin          transport.ReceiveOrigin
	StreamRun       string
	Stream          uint64
	// Scope references are frozen at dispatch/lifecycle entry and after its
	// checking-context update. They remain observation-only identifiers.
	ReceiveLedgerRun                                     string
	ReceiveLedger, ReceiveScopeBefore, ReceiveScopeAfter uint64
	Before, After                                        transport.ValidationContext
	BeforeKnown, AfterKnown                              bool
	Entry, Observed                                      CoreStepMoment
	Unavailable                                          string
}

// DecodeCoreEnvironment restores public validator keys without treating a
// decoded empty byte string as proof that an originally nil key was present.
func DecodeCoreEnvironment(e CoreEnvObservation) (inputlog.EnvCall, error) {
	c, err := inputlog.DecodeEnv(e.Bytes)
	if err != nil {
		return inputlog.EnvCall{}, err
	}
	if c.Kind != inputlog.EnvValidatorsAt && c.Kind != inputlog.EnvValidateProposal && c.Kind != inputlog.EnvIsBadBlock {
		return inputlog.EnvCall{}, fmt.Errorf("journal: unsupported core environment answer")
	}
	if c.Kind != inputlog.EnvValidatorsAt || c.Validators == nil {
		if len(e.ValidatorKeyPresent) != 0 || c.Kind != inputlog.EnvValidatorsAt && c.Validators != nil {
			return inputlog.EnvCall{}, fmt.Errorf("journal: unrelated authority witness")
		}
		return canonicalCoreEnvironment(e, c)
	}
	if len(e.ValidatorKeyPresent) != c.Validators.Len() {
		return inputlog.EnvCall{}, fmt.Errorf("journal: incomplete ordered authority witness")
	}
	keys := make([][]byte, c.Validators.Len())
	for i, present := range e.ValidatorKeyPresent {
		key := c.Validators.At(i).BLSPublicKey
		if present {
			keys[i] = append([]byte{}, key...)
		} else if len(key) != 0 {
			return inputlog.EnvCall{}, fmt.Errorf("journal: absent authority key has bytes")
		}
	}
	c.Validators, err = validator.NewSet(c.Validators.Addresses(), keys, c.Validators.Policy())
	if err != nil {
		return inputlog.EnvCall{}, err
	}
	return canonicalCoreEnvironment(e, c)
}

func canonicalCoreEnvironment(e CoreEnvObservation, c inputlog.EnvCall) (inputlog.EnvCall, error) {
	encoded, err := inputlog.EncodeEnv(c)
	if err != nil || !bytes.Equal(encoded, e.Bytes) {
		return inputlog.EnvCall{}, fmt.Errorf("journal: noncanonical core environment answer")
	}
	return c, nil
}

type coreEnvRLP struct {
	Bytes      []byte
	KeyPresent []uint64
}
type coreStepRLP struct {
	CoreSelf                                             types.Address
	Improvements, BacklogLimit                           uint64
	Head                                                 []byte
	Format, Profile, JSeq, EngineRun, Step, Flags        uint64
	Via, InputKind                                       string
	Input, Outputs                                       []byte
	OutDigest                                            types.Hash
	Environment                                          []coreEnvRLP
	Origin                                               transport.ReceiveOrigin
	StreamRun                                            string
	Stream                                               uint64
	ReceiveLedgerRun                                     string
	ReceiveLedger, ReceiveScopeBefore, ReceiveScopeAfter uint64
	Before, After                                        validationContextRLP
	EntryMono, EntryWall, ObservedMono, ObservedWall     uint64
	Unavailable                                          string
	RetryMaximumMs                                       uint64 `rlp:"optional"`
}

func validCoreStepSource(s *CoreStepRec) bool {
	if s.RetryMaximumMs != 0 && (&RoundChangeRetryOptions{Profile: RoundChangeRetryProfile, MaxIntervalMs: s.RetryMaximumMs}).Validate() != nil {
		return false
	}
	if s.EngineRun == 0 || s.Step == 0 || !validReceiveOrigin(s.Origin) || s.StreamRun != "" && s.Stream == 0 {
		return false
	}
	if s.ReceiveLedgerRun != "" && s.ReceiveLedger == 0 || s.ReceiveLedger == 0 && (s.ReceiveScopeBefore != 0 || s.ReceiveScopeAfter != 0) {
		return false
	}
	switch s.Via {
	case "engine", "internal", "app", "timer", "peer", "wal":
	default:
		return false
	}
	if s.BeforeKnown {
		if !validValidationContext(s.Before) {
			return false
		}
	} else if s.Before != (transport.ValidationContext{}) {
		return false
	}
	if s.AfterKnown {
		if !validValidationContext(s.After) {
			return false
		}
	} else if s.After != (transport.ValidationContext{}) {
		return false
	}
	switch s.Unavailable {
	case "", "output_encoding", "output_digest", "environment_encoding", "head_encoding":
	default:
		return false
	}
	if s.Unavailable == "" && (len(s.Outputs) == 0 || keccak.Sum256(s.Outputs) != s.OutDigest) {
		return false
	}
	if _, err := inputlog.Decode(s.InputKind, s.Input, nil); err != nil {
		return false
	}
	if len(s.Head) > 0 {
		if _, err := codec.DecodeHeader(s.Head); err != nil {
			return false
		}
	}
	for _, e := range s.Environment {
		if _, err := DecodeCoreEnvironment(e); err != nil {
			return false
		}
	}
	return true
}

func encodeCoreStepRec(s *CoreStepRec, jseq uint64) ([]byte, error) {
	if !validCoreStepSource(s) {
		return nil, fmt.Errorf("journal: invalid core step source")
	}
	w := coreStepRLP{Format: Format, Profile: 1, JSeq: jseq, EngineRun: s.EngineRun, Step: s.Step, Via: s.Via, InputKind: s.InputKind, Input: s.Input, Outputs: s.Outputs, OutDigest: s.OutDigest, Origin: s.Origin, StreamRun: s.StreamRun, Stream: s.Stream, Before: receiveContextWire(s.Before), After: receiveContextWire(s.After), EntryMono: uint64(s.Entry.Mono), EntryWall: uint64(s.Entry.WallNs), ObservedMono: uint64(s.Observed.Mono), ObservedWall: uint64(s.Observed.WallNs), Unavailable: s.Unavailable}
	w.CoreSelf, w.Improvements, w.BacklogLimit, w.Head = s.CoreSelf, s.Improvements, uint64(s.BacklogLimit), s.Head
	w.RetryMaximumMs = s.RetryMaximumMs
	w.ReceiveLedgerRun, w.ReceiveLedger, w.ReceiveScopeBefore, w.ReceiveScopeAfter = s.ReceiveLedgerRun, s.ReceiveLedger, s.ReceiveScopeBefore, s.ReceiveScopeAfter
	for i, flag := range []bool{s.ReplayedPrefix, s.BeforeKnown, s.AfterKnown} {
		if flag {
			w.Flags |= 1 << i
		}
	}
	for _, env := range s.Environment {
		e := coreEnvRLP{Bytes: env.Bytes}
		for _, present := range env.ValidatorKeyPresent {
			e.KeyPresent = append(e.KeyPresent, boolUint(present))
		}
		w.Environment = append(w.Environment, e)
	}
	return rlp.Encode(&w)
}

func decodeCoreStepRec(body []byte) (Record, error) {
	var w coreStepRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: core step source: %v", ErrRecord, err)
	}
	if w.Format != Format || w.Profile != 1 || w.Flags&^uint64(7) != 0 || w.Before.ValidatorsPresent > 1 || w.Before.PriorValidatorsPresent > 1 || w.After.ValidatorsPresent > 1 || w.After.PriorValidatorsPresent > 1 {
		return Record{}, fmt.Errorf("%w: core step source flags/profile", ErrRecord)
	}
	s := &CoreStepRec{EngineRun: w.EngineRun, Step: w.Step, ReplayedPrefix: w.Flags&1 != 0, BeforeKnown: w.Flags&2 != 0, AfterKnown: w.Flags&4 != 0, Via: w.Via, InputKind: w.InputKind, Input: w.Input, Outputs: w.Outputs, OutDigest: w.OutDigest, Origin: w.Origin, StreamRun: w.StreamRun, Stream: w.Stream, Before: receiveContextValue(w.Before), After: receiveContextValue(w.After), Entry: CoreStepMoment{Mono: int64(w.EntryMono), WallNs: int64(w.EntryWall)}, Observed: CoreStepMoment{Mono: int64(w.ObservedMono), WallNs: int64(w.ObservedWall)}, Unavailable: w.Unavailable}
	s.CoreSelf, s.Improvements, s.BacklogLimit, s.Head = w.CoreSelf, w.Improvements, int64(w.BacklogLimit), w.Head
	s.RetryMaximumMs = w.RetryMaximumMs
	s.ReceiveLedgerRun, s.ReceiveLedger, s.ReceiveScopeBefore, s.ReceiveScopeAfter = w.ReceiveLedgerRun, w.ReceiveLedger, w.ReceiveScopeBefore, w.ReceiveScopeAfter
	for _, e := range w.Environment {
		env := CoreEnvObservation{Bytes: e.Bytes}
		for _, present := range e.KeyPresent {
			if present > 1 {
				return Record{}, fmt.Errorf("%w: core authority presence flag", ErrRecord)
			}
			env.ValidatorKeyPresent = append(env.ValidatorKeyPresent, present == 1)
		}
		s.Environment = append(s.Environment, env)
	}
	if !validCoreStepSource(s) {
		return Record{}, fmt.Errorf("%w: invalid core step source", ErrRecord)
	}
	return Record{Kind: KindCoreStep, JSeq: w.JSeq, Body: s}, nil
}
