package stepdriver

import (
	"errors"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"testing"
)

func TestRecordedAnswersFollowArgumentKeysAndAreConsumedOnce(t *testing.T) {
	a, b := types.Hash{1}, types.Hash{2}
	env := &traceEnv{answers: []inputlog.EnvCall{
		{Kind: inputlog.EnvIsBadBlock, Key: a, Bad: false},
		{Kind: inputlog.EnvIsBadBlock, Key: b, Bad: true},
		{Kind: inputlog.EnvIsBadBlock, Key: a, Bad: true},
	}}
	if !env.IsBadBlock(b) || env.IsBadBlock(a) || !env.IsBadBlock(a) || env.err != nil || len(env.calls) != 3 {
		t.Fatal(env.calls, env.err)
	}
	env.IsBadBlock(a)
	if !errors.Is(env.err, ErrTraceEnvExhausted) || len(env.calls) != 3 {
		t.Fatal("an absent answer was reused", env.calls, env.err)
	}
}

func TestTraceRefusesConfigurationChangeWithinWriter(t *testing.T) {
	first := &journal.SegmentRec{Identity: journal.Identity{Run: "synthetic-run", Core: journal.CoreOptions{ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{}}}`), Self: types.Address{1}}}}
	changed := *first
	changed.Core.Self = types.Address{2}
	r := &coverageReader{records: []journal.Record{{Body: first}, {Body: &changed}}}
	if err := RunTrace(r, TraceOptions{}, func(StepResult) error { return nil }); !errors.Is(err, ErrTraceConfiguration) {
		t.Fatal("configuration change accepted", err)
	}
}
