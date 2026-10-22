package stepdriver

import (
	"errors"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestCachePolicyDeclarationDoesNotEnableReplay(t *testing.T) {
	segment := &journal.SegmentRec{Identity: journal.Identity{Run: "cache-writer", Core: journal.CoreOptions{
		ChainConfig: []byte(`{"anzeon":{"wbft":{}}}`),
		CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16}},
	}}}
	reader := func() *coverageReader {
		return &coverageReader{records: []journal.Record{{JSeq: 1, Kind: journal.KindSegment, Body: segment}}}
	}
	if _, err := NewAnswerPool(reader()); !errors.Is(err, journal.ErrCachePolicyReplay) {
		t.Fatal("unsupported runtime source indexed as replayable", err)
	}
	emitted := 0
	if err := RunTrace(reader(), TraceOptions{}, func(StepResult) error { emitted++; return nil }); !errors.Is(err, journal.ErrCachePolicyReplay) || emitted != 0 {
		t.Fatal("unimplemented cache policy reported a replayed prefix", err, emitted)
	}
}
