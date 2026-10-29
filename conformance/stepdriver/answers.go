package stepdriver

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

const MaxAnswerRecords = 1000000
const MaxAnswerSteps = 100000
const MaxApplicationAnswers = 100000
const MaxApplicationAnswerBytes = 16 << 20

var ErrTraceEnvAmbiguous = errors.New("stepdriver: recorded application answers conflict")
var ErrTraceEnvSource = errors.New("stepdriver: recorded application answer source mismatch")
var ErrTraceAnswerLimit = errors.New("stepdriver: recorded application answer limit exceeded")

type AnswerSource struct {
	WriterRun string     `json:"writer_run"`
	EngineRun uint64     `json:"engine_run"`
	Step      uint64     `json:"step"`
	Call      int        `json:"call"`
	Kind      uint8      `json:"kind"`
	Key       types.Hash `json:"key"`
}

type answerCoordinate struct {
	writer       string
	engine, step uint64
}
type answerContext struct {
	writer       string
	engine       uint64
	head         string
	hash, valset types.Hash
}
type answerKey struct {
	context answerContext
	kind    uint8
	key     types.Hash
}
type recordedAnswer struct {
	source  AnswerSource
	call    inputlog.EnvCall
	encoded []byte
}
type answerStep struct {
	context answerContext
	digest  [32]byte
	entries []int
}

// AnswerPool indexes application responses from one retained source. It is
// immutable after construction; every RunTrace uses a fresh consumption session.
// Cross-step lookup requires identical writer, engine, head and validator context.
type AnswerPool struct {
	configurations map[string][32]byte
	steps          map[answerCoordinate]answerStep
	keys           map[answerKey][]int
	entries        []recordedAnswer
}

func answerContextOf(writer string, b *journal.StepRec) answerContext {
	return answerContext{writer: writer, engine: b.EngineRun, head: b.HeadNumber.String(), hash: b.HeadHash, valset: b.ValsetDigest}
}
func answerDigest(b *journal.StepRec) ([32]byte, error) {
	if b.HeadNumber.Big().BitLen() > 512 {
		return [32]byte{}, ErrTraceEnvSource
	}
	total := 0
	for _, raw := range b.Env {
		if len(raw) > MaxApplicationAnswerBytes-total {
			return [32]byte{}, ErrTraceAnswerLimit
		}
		total += len(raw)
	}
	raw, err := json.Marshal(struct {
		Head         string
		Hash, Valset types.Hash
		Count        int
	}{b.HeadNumber.String(), b.HeadHash, b.ValsetDigest, len(b.Env)})
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write(raw)
	var length [8]byte
	for _, raw := range b.Env {
		binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(raw)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func NewAnswerPool(j JournalReader) (*AnswerPool, error) {
	if j == nil {
		return nil, ErrTraceEnvSource
	}
	p := &AnswerPool{configurations: map[string][32]byte{}, steps: map[answerCoordinate]answerStep{}, keys: map[answerKey][]int{}}
	writer := ""
	priorProfile := false
	var lastSeq, lastStep, lastEngine uint64
	totalBytes := 0
	for count := 0; ; count++ {
		rec, err := j.Next()
		if err == io.EOF {
			return p, nil
		}
		if err != nil {
			return nil, err
		}
		if count >= MaxAnswerRecords {
			return nil, ErrTraceAnswerLimit
		}
		if seg, ok := rec.Body.(*journal.SegmentRec); ok && seg.Run != writer {
			lastSeq, lastStep, lastEngine = 0, 0, 0
		}
		if rec.JSeq == 0 || lastSeq != 0 && rec.JSeq != lastSeq+1 {
			return nil, ErrTraceGap
		}
		lastSeq = rec.JSeq
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			flags := consensus.ImprovementSet(b.Core.Improvements)
			priorProfile = flags.Has(consensus.BindPriorHead) || flags.Has(consensus.DeferValidatorStart)
			if err := b.Core.ValidateRuntimeProfiles(); err != nil {
				return nil, err
			}
			if len(b.Core.ChainConfig) > MaxApplicationAnswerBytes {
				return nil, ErrTraceAnswerLimit
			}
			raw, err := json.Marshal(b.Core)
			if err != nil {
				return nil, err
			}
			if len(raw) > MaxApplicationAnswerBytes || b.Run == "" {
				return nil, ErrTraceEnvSource
			}
			hash := sha256.Sum256(raw)
			if prior, ok := p.configurations[b.Run]; ok && prior != hash {
				return nil, ErrTraceConfiguration
			}
			p.configurations[b.Run] = hash
			writer = b.Run
		case *journal.GapRec:
			return nil, ErrTraceGap
		case *journal.StepRec:
			if writer == "" || b.Step == 0 || b.EngineRun == 0 {
				return nil, ErrTraceEnvSource
			}
			if lastStep != 0 && b.InputKind != inputlog.KindStart && (b.EngineRun != lastEngine || b.Step != lastStep+1) {
				return nil, ErrTraceGap
			}
			lastStep, lastEngine = b.Step, b.EngineRun
			if len(p.steps) >= MaxAnswerSteps {
				return nil, ErrTraceAnswerLimit
			}
			coord := answerCoordinate{writer, b.EngineRun, b.Step}
			if _, exists := p.steps[coord]; exists {
				return nil, ErrTraceEnvSource
			}
			if b.HeadNumber.Big().BitLen() > 512 {
				return nil, ErrTraceEnvSource
			}
			c := answerContextOf(writer, b)
			digest, err := answerDigest(b)
			if err != nil {
				return nil, err
			}
			step := answerStep{context: c, digest: digest}
			for i, raw := range b.Env {
				if len(raw) > MaxApplicationAnswerBytes-totalBytes || len(p.entries) >= MaxApplicationAnswers {
					return nil, ErrTraceAnswerLimit
				}
				totalBytes += len(raw)
				call, err := inputlog.DecodeEnv(raw)
				if err != nil {
					return nil, err
				}
				if call.Kind == inputlog.EnvValidatorsAt {
					if !priorProfile || call.Result != 0 || call.Future != 0 || call.Step != "" || call.Class != "" || call.Bad {
						return nil, ErrTraceEnvSource
					}
					encoded, err := inputlog.EncodeEnv(call)
					if err != nil || !bytes.Equal(encoded, raw) {
						return nil, ErrTraceEnvSource
					}
					continue
				}
				if call.Kind != inputlog.EnvValidateProposal && call.Kind != inputlog.EnvIsBadBlock {
					return nil, ErrTraceEnvSource
				}
				encoded, err := inputlog.EncodeEnv(call)
				if err != nil {
					return nil, err
				}
				if !bytes.Equal(encoded, raw) {
					return nil, ErrTraceEnvSource
				}
				entry := len(p.entries)
				p.entries = append(p.entries, recordedAnswer{source: AnswerSource{writer, b.EngineRun, b.Step, i + 1, call.Kind, call.Key}, call: call, encoded: encoded})
				key := answerKey{c, call.Kind, call.Key}
				p.keys[key] = append(p.keys[key], entry)
				step.entries = append(step.entries, entry)
			}
			p.steps[coord] = step
		}
	}
}

type answerSession struct {
	pool *AnswerPool
	used []bool
}

func (p *AnswerPool) session() *answerSession { return &answerSession{p, make([]bool, len(p.entries))} }
func (s *answerSession) validateSegment(b *journal.SegmentRec) error {
	raw, err := json.Marshal(b.Core)
	if err != nil {
		return err
	}
	expected, ok := s.pool.configurations[b.Run]
	if !ok || expected != sha256.Sum256(raw) {
		return ErrTraceEnvSource
	}
	return nil
}
func (s *answerSession) source(writer string, b *journal.StepRec) (answerStep, error) {
	coord := answerCoordinate{writer, b.EngineRun, b.Step}
	entry, ok := s.pool.steps[coord]
	digest, err := answerDigest(b)
	if err != nil {
		return answerStep{}, err
	}
	if !ok || entry.context != answerContextOf(writer, b) || entry.digest != digest {
		return answerStep{}, ErrTraceEnvSource
	}
	return entry, nil
}
func (s *answerSession) pop(step answerStep, kind uint8, key types.Hash) (inputlog.EnvCall, AnswerSource, error) {
	take := func(i int) (inputlog.EnvCall, AnswerSource, error) {
		s.used[i] = true
		e := s.pool.entries[i]
		return e.call, e.source, nil
	}
	for _, i := range step.entries {
		e := s.pool.entries[i]
		if !s.used[i] && e.call.Kind == kind && e.call.Key == key {
			return take(i)
		}
	}
	candidates := s.pool.keys[answerKey{step.context, kind, key}]
	first, reference := -1, -1
	conflict := false
	for _, i := range candidates {
		if reference < 0 {
			reference = i
		} else if !bytes.Equal(s.pool.entries[reference].encoded, s.pool.entries[i].encoded) {
			conflict = true
		}
		if first < 0 && !s.used[i] {
			first = i
		}
	}
	if first < 0 {
		return inputlog.EnvCall{}, AnswerSource{}, ErrTraceEnvExhausted
	}
	if conflict {
		return inputlog.EnvCall{}, AnswerSource{}, ErrTraceEnvAmbiguous
	}
	return take(first)
}
