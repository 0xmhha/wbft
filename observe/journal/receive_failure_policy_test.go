package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
)

func failureDeclarationPolicy() *CachePolicyOptions {
	return &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}
}

func TestReceiveFailureDeclarationPreservesPreviousHeaderBytes(t *testing.T) {
	for _, tail := range []int{0, 1, 5, 6, 8} {
		id := ident()
		id.Core = CoreOptions{ChainConfig: []byte(`{"anzeon":{"wbft":{}}}`)}
		switch tail {
		case 1:
			id.Core.TimerTrace = 1
		case 5:
			id.Core.NextHeight = &DeferredOptions{Profile: DeferredInputProfile, Entries: 8, Bytes: 1024, PerPeer: 4, PerSource: 4}
		case 6:
			id.Core.CachePolicy = failureDeclarationPolicy()
		case 8:
			id.Core.CachePolicy = failureDeclarationPolicy()
			id.Core.RoundChangeRetry = &RoundChangeRetryOptions{Profile: RoundChangeRetryProfile, MaxIntervalMs: 8000}
		}
		// The complete previous field list is a frozen compatibility contract,
		// independent of the new optional field and its encoder.
		fields := []any{uint64(Format), uint64(1), id.Self, bytesOrEmpty(id.NodeID), bytesOrEmpty(id.BLSPublicKey), id.Run, id.Commit, bigOrZero(id.ChainID), id.GenesisHash, id.Mode, id.WireOffset, id.ConfigDigest, id.Core.ChainConfig, id.Core.Self, id.Core.Improvements, id.Core.BacklogLimit, id.Core.Profile, uint64(0)}
		observation, err := id.Core.Observation.encode()
		if err != nil {
			t.Fatal(err)
		}
		previousOptional := []any{id.Core.TimerTrace, id.Core.CacheTrace, id.Core.SyncTrace, id.Core.ProposerPolicyProfile, id.Core.NextHeight.encode(), id.Core.CachePolicy.encode(), observation, id.Core.RoundChangeRetry.encode()}
		fields = append(fields, previousOptional[:tail]...)
		want, err := rlp.Encode(fields)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("absent failure declaration changed the previous header with tail=%d: %v", tail, err)
		}
		encoded, err := json.Marshal(id.Core)
		if err != nil || bytes.Contains(encoded, []byte("receive_failure_cache")) {
			t.Fatal("absent declaration changed legacy JSON", err)
		}
	}
}

func TestReceiveFailureDeclarationRoundTripAndCapabilities(t *testing.T) {
	for _, profile := range []uint64{ReceiveFailureCacheProfile, 2} {
		id := ident()
		id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
		id.Core.CachePolicy = failureDeclarationPolicy()
		id.Core.ReceiveFailureCache = &ReceiveFailureCacheOptions{Profile: profile, Entries: 2}
		raw, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindSegment, raw)
		if err != nil {
			t.Fatal(err)
		}
		got := decoded.Body.(*SegmentRec).Core
		if !reflect.DeepEqual(got.ReceiveFailureCache, id.Core.ReceiveFailureCache) {
			t.Fatal("declaration was discarded or normalized")
		}
		if profile == ReceiveFailureCacheProfile {
			if err := got.ValidateReceiveFailureDeclaration(&transport.ReceiveFailureOptions{Entries: 2}); err != nil {
				t.Fatal(err)
			}
			if err := got.ValidateReceiveFailureDeclaration(&transport.ReceiveFailureOptions{Entries: 3}); err == nil {
				t.Fatal("actual entry limit was not bound")
			}
			if err := got.ValidateReceiveFailureDeclaration(nil); err == nil {
				t.Fatal("declared policy became disabled without a mismatch")
			}
			if err := got.ValidateRuntimeProfiles(); !errors.Is(err, ErrReceiveFailureReplay) {
				t.Fatal("declaration implied functional replay capability", err)
			}
		} else if got.ReceiveFailureCache.Validate() == nil {
			t.Fatal("unknown decoded declaration became supported")
		}
	}
	options := CoreOptions{ReceiveFailureCache: &ReceiveFailureCacheOptions{Profile: ReceiveFailureCacheProfile, Entries: 2}}
	if err := options.ValidateReceiveFailureDeclaration(&transport.ReceiveFailureOptions{Entries: 2}); err == nil {
		t.Fatal("failure declaration omitted its accepted-input prerequisite")
	}
}

func TestReceiveFailureDeclarationFrozenAcrossNormalRotation(t *testing.T) {
	id := ident()
	id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
	id.Core.CachePolicy = failureDeclarationPolicy()
	id.Core.ReceiveFailureCache = &ReceiveFailureCacheOptions{Profile: ReceiveFailureCacheProfile, Entries: 2}
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/failure-header", Synchronous: true, SegmentBytes: 400}, id)
	if err != nil {
		t.Fatal(err)
	}
	id.Core.ReceiveFailureCache.Entries = 3
	copy := w.CoreDeclaration()
	copy.ReceiveFailureCache.Entries = 4
	if w.CoreDeclaration().ReceiveFailureCache.Entries != 2 {
		t.Fatal("caller mutated the frozen declaration")
	}
	for request := uint64(1); request <= 8; request++ {
		w.Put(Record{Body: &SyncRec{Stage: "requested", Request: request, Syncing: true, Mono: time.Duration(request)}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/failure-header")
	if err != nil {
		t.Fatal(err)
	}
	segments := 0
	for _, record := range records {
		if segment, ok := record.Body.(*SegmentRec); ok {
			segments++
			if segment.Core.ReceiveFailureCache.Entries != 2 {
				t.Fatal("normal rotation rebound frozen limits")
			}
		}
	}
	if segments < 2 {
		t.Fatal("normal rotation was not exercised")
	}
}

func TestReceiveFailureDeclarationDoesNotEnableOldSourceInspector(t *testing.T) {
	id := ident()
	id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
	id.Core.CachePolicy = failureDeclarationPolicy()
	id.Core.ReceiveFailureCache = &ReceiveFailureCacheOptions{Profile: ReceiveFailureCacheProfile, Entries: 2}
	check, err := CheckCoreStepSources([]Record{{Body: &SegmentRec{Identity: id}}}, CoreSourceLimits{Records: 100, Runs: 4, Steps: 100, Environments: 100, Outputs: 100, Bytes: 1 << 20})
	if err != nil || check.Status != "unavailable" || check.Reason != "receive_failure_source_profile_unavailable" {
		t.Fatal("old inspector silently accepted the new policy", check, err)
	}
}
