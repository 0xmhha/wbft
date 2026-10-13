package stepdriver

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func answerFixture(t *testing.T) (*AnswerPool, []*journal.StepRec) {
	t.Helper()
	a, b, c := types.Hash{1}, types.Hash{2}, types.Hash{3}
	calls := [][]inputlog.EnvCall{
		{{Kind: inputlog.EnvIsBadBlock, Key: a, Bad: false}},
		{{Kind: inputlog.EnvIsBadBlock, Key: b, Bad: true}, {Kind: inputlog.EnvIsBadBlock, Key: c, Bad: true}},
		{{Kind: inputlog.EnvIsBadBlock, Key: c, Bad: false}},
	}
	segment := &journal.SegmentRec{Identity: journal.Identity{Run: "writer-one", Core: journal.CoreOptions{ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{}}}`), Self: types.Address{1}}}}
	records := []journal.Record{{Body: segment}}
	var steps []*journal.StepRec
	for i, list := range calls {
		step := &journal.StepRec{EngineRun: 1, Step: uint64(i + 1), HeadNumber: types.HeightFromUint64(4), HeadHash: types.Hash{4}, ValsetDigest: types.Hash{5}}
		for _, call := range list {
			raw, err := inputlog.EncodeEnv(call)
			if err != nil {
				t.Fatal(err)
			}
			step.Env = append(step.Env, raw)
		}
		steps = append(steps, step)
		records = append(records, journal.Record{Body: step})
	}
	for i := range records {
		records[i].JSeq = uint64(i + 1)
	}
	pool, err := NewAnswerPool(&coverageReader{records: records})
	if err != nil {
		t.Fatal(err)
	}
	return pool, steps
}

func TestContextAnswersUseSourceKeysOnceAndRetainProvenance(t *testing.T) {
	pool, steps := answerFixture(t)
	session := pool.session()
	source, err := session.source("writer-one", steps[0])
	if err != nil {
		t.Fatal(err)
	}
	answer, where, err := session.pop(source, inputlog.EnvIsBadBlock, types.Hash{2})
	if err != nil || !answer.Bad || where.WriterRun != "writer-one" || where.EngineRun != 1 || where.Step != 2 || where.Call != 1 {
		t.Fatal(answer, where, err)
	}
	second, err := session.source("writer-one", steps[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = session.pop(second, inputlog.EnvIsBadBlock, types.Hash{2}); !errors.Is(err, ErrTraceEnvExhausted) {
		t.Fatal("answer reused", err)
	}
	fresh := pool.session()
	source, err = fresh.source("writer-one", steps[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = fresh.pop(source, inputlog.EnvIsBadBlock, types.Hash{2}); err != nil {
		t.Fatal("pool consumption leaked to another run", err)
	}
}

func TestContextAnswersRefuseConflictsAndForeignContexts(t *testing.T) {
	pool, steps := answerFixture(t)
	session := pool.session()
	source, err := session.source("writer-one", steps[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = session.pop(source, inputlog.EnvIsBadBlock, types.Hash{3}); !errors.Is(err, ErrTraceEnvAmbiguous) {
		t.Fatal("conflicting answers guessed", err)
	}
	if _, _, err = session.pop(source, inputlog.EnvValidateProposal, types.Hash{2}); !errors.Is(err, ErrTraceEnvExhausted) {
		t.Fatal("call kind ignored", err)
	}
	for _, change := range []func(*answerContext){
		func(c *answerContext) { c.writer = "other-writer" }, func(c *answerContext) { c.engine = 2 }, func(c *answerContext) { c.head = "5" }, func(c *answerContext) { c.hash = types.Hash{6} }, func(c *answerContext) { c.valset = types.Hash{7} },
	} {
		foreign := source
		change(&foreign.context)
		if _, _, err = session.pop(foreign, inputlog.EnvIsBadBlock, types.Hash{2}); !errors.Is(err, ErrTraceEnvExhausted) {
			t.Fatal("foreign context used", err)
		}
	}
	local, err := session.source("writer-one", steps[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = session.pop(local, inputlog.EnvIsBadBlock, types.Hash{3}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = session.pop(source, inputlog.EnvIsBadBlock, types.Hash{3}); !errors.Is(err, ErrTraceEnvAmbiguous) {
		t.Fatal("consumption hid a conflicting original response", err)
	}
	changed := *steps[0]
	changed.Env = steps[1].Env
	if _, err = session.source("writer-one", &changed); !errors.Is(err, ErrTraceEnvSource) {
		t.Fatal("source responses changed", err)
	}
}

func TestContextAnswersPreferTheOriginalStepAndKeepRepeatedResponses(t *testing.T) {
	pool, steps := answerFixture(t)
	session := pool.session()
	source, err := session.source("writer-one", steps[1])
	if err != nil {
		t.Fatal(err)
	}
	if call, _, err := session.pop(source, inputlog.EnvIsBadBlock, types.Hash{3}); err != nil || !call.Bad {
		t.Fatal(call, err)
	}
	source, err = session.source("writer-one", steps[2])
	if err != nil {
		t.Fatal(err)
	}
	if call, _, err := session.pop(source, inputlog.EnvIsBadBlock, types.Hash{3}); err != nil || call.Bad {
		t.Fatal(call, err)
	}
	// Delayed proposal answers must not be inferred from a different response.
	a := inputlog.ProposalCall(types.Hash{8}, time.Second, header.ErrFutureBlock)
	b := inputlog.ProposalCall(types.Hash{8}, 2*time.Second, header.ErrFutureBlock)
	rawA, _ := inputlog.EncodeEnv(a)
	rawB, _ := inputlog.EncodeEnv(b)
	pool.entries = append(pool.entries, recordedAnswer{call: a, encoded: rawA}, recordedAnswer{call: b, encoded: rawB})
	key := answerKey{source.context, inputlog.EnvValidateProposal, types.Hash{8}}
	pool.keys[key] = []int{len(pool.entries) - 2, len(pool.entries) - 1}
	session = pool.session()
	if _, _, err = session.pop(source, inputlog.EnvValidateProposal, types.Hash{8}); !errors.Is(err, ErrTraceEnvAmbiguous) {
		t.Fatal("future duration guessed", err)
	}
}

type headSource struct {
	number *types.Header
	block  *types.Block
}

func (s headSource) HeaderByNumber(types.Height) (*types.Header, error) { return s.number, nil }
func (s headSource) BlockByHash(types.Hash) (*types.Block, error)       { return s.block, nil }
func TestRecordedHeadChecksNumberHashAndNilFallback(t *testing.T) {
	h := &types.Header{Number: types.HeightFromUint64(5)}
	hash := codec.BlockHash(h)
	for _, source := range []headSource{{number: h, block: &types.Block{Header: h}}, {block: &types.Block{Header: h}}, {block: &types.Block{}}, {}} {
		if _, err := headOf(source, types.HeightFromUint64(4), hash); !errors.Is(err, ErrTraceHeadMismatch) {
			t.Fatal("wrong head accepted", err)
		}
	}
	if got, err := headOf(headSource{block: &types.Block{Header: h}}, types.HeightFromUint64(5), hash); err != nil || got != h {
		t.Fatal(got, err)
	}
	if _, err := headOf(headSource{block: &types.Block{Header: h}}, types.HeightFromUint64(5), types.Hash{9}); !errors.Is(err, ErrTraceHeadMismatch) {
		t.Fatal("wrong hash accepted", err)
	}
}

type unlimitedAnswerRecords struct{ seq uint64 }

func (r *unlimitedAnswerRecords) Next() (journal.Record, error) {
	r.seq++
	return journal.Record{JSeq: r.seq, Body: &journal.PeerRec{}}, nil
}
func TestAnswerPoolBoundsAndSourceGaps(t *testing.T) {
	if _, err := NewAnswerPool(nil); !errors.Is(err, ErrTraceEnvSource) {
		t.Fatal(err)
	}
	if _, err := NewAnswerPool(&unlimitedAnswerRecords{}); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("unbounded records accepted", err)
	}
	segment := journal.Record{JSeq: 1, Body: &journal.SegmentRec{Identity: journal.Identity{Run: "bounded-source", Core: journal.CoreOptions{ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{}}}`)}}}}
	step := &journal.StepRec{EngineRun: 1, Step: 1, Env: [][]byte{make([]byte, MaxApplicationAnswerBytes+1)}}
	if _, err := NewAnswerPool(&coverageReader{records: []journal.Record{segment, {JSeq: 2, Body: step}}}); !errors.Is(err, ErrTraceAnswerLimit) {
		t.Fatal("oversized responses accepted", err)
	}
	step = &journal.StepRec{EngineRun: 1, Step: 1}
	for _, records := range [][]journal.Record{
		{segment, {JSeq: 3, Body: step}},
		{segment, {JSeq: 2, Body: &journal.GapRec{Dropped: 1}}},
		{segment, {JSeq: 2, Body: step}, {JSeq: 3, Body: &journal.StepRec{EngineRun: 1, Step: 3}}},
	} {
		if _, err := NewAnswerPool(&coverageReader{records: records}); !errors.Is(err, ErrTraceGap) {
			t.Fatal("source gap accepted", err)
		}
	}
	pool, _ := answerFixture(t)
	changed := segment.Body.(*journal.SegmentRec)
	changed.Core.Self = types.Address{9}
	changed.Run = "writer-one"
	if err := pool.session().validateSegment(changed); !errors.Is(err, ErrTraceEnvSource) {
		t.Fatal("foreign configuration accepted", err)
	}
}
