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

func TestCachePolicyHeaderPreservesLegacyBytes(t *testing.T) {
	for _, deferred := range []*DeferredOptions{nil, {Profile: DeferredInputProfile, Entries: 12, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}} {
		id := ident()
		id.Core = CoreOptions{ChainConfig: []byte(`{"anzeon":{"wbft":{}}}`), ProposerPolicyProfile: CheckedProposerPolicyProfile, NextHeight: deferred}
		raw, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		// Freeze the complete pre-cache-policy field list, including the
		// optional receive profile only when it existed in that old header.
		fields := []any{uint64(Format), uint64(1), id.Self, bytesOrEmpty(id.NodeID), bytesOrEmpty(id.BLSPublicKey), id.Run, id.Commit, bigOrZero(id.ChainID), id.GenesisHash, id.Mode, id.WireOffset, id.ConfigDigest, id.Core.ChainConfig, id.Core.Self, uint64(0), uint64(0), "", uint64(0), uint64(0), uint64(0), uint64(0), CheckedProposerPolicyProfile}
		if deferred != nil {
			fields = append(fields, deferred.encode())
		}
		before, err := rlp.Encode(fields)
		if err != nil || !bytes.Equal(before, raw) {
			t.Fatal("absent cache policy changed legacy segment bytes", err)
		}
		encoded, err := json.Marshal(id.Core)
		if err != nil || bytes.Contains(encoded, []byte("cache_policy")) {
			t.Fatal("absent policy changed the JSON declaration", err)
		}
	}
}

func TestCachePolicyHeaderExactLimitsAndCapability(t *testing.T) {
	id := ident()
	id.Core.ChainConfig = []byte(`{"anzeon":{"wbft":{}}}`)
	limits := transport.CachePolicyLimits{ReceivePending: 9007199254740993, ReceivePerPeer: 8, WritePending: ^uint64(0), WritePerPeer: 16}
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: limits}
	for _, profile := range []uint64{AcceptedCompletedCacheProfile, 77} {
		id.Core.CachePolicy.Profile = profile
		raw, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		record, err := decodeBody(KindSegment, raw)
		if err != nil {
			t.Fatal(err)
		}
		got := record.Body.(*SegmentRec).Core
		if !reflect.DeepEqual(got.CachePolicy, id.Core.CachePolicy) {
			t.Fatal("cache profile or exact integer limits changed")
		}
		encoded, err := json.Marshal(got.CachePolicy)
		if err != nil || !bytes.Contains(encoded, []byte(`"receive_pending":"9007199254740993"`)) || !bytes.Contains(encoded, []byte(`"write_pending":"18446744073709551615"`)) {
			t.Fatal("integer precision lost in JSON", err)
		}
		if profile == AcceptedCompletedCacheProfile {
			if err := got.CachePolicy.Validate(); err != nil {
				t.Fatal(err)
			}
			if _, err := got.Configuration(); !errors.Is(err, ErrCachePolicyReplay) {
				t.Fatal("recognized declaration became an unimplemented replay capability", err)
			}
		} else if got.CachePolicy.Validate() == nil {
			t.Fatal("unknown cache policy treated as supported")
		}
	}
	if _, err := decodeCachePolicyOptions([]uint64{1, 2}); err == nil {
		t.Fatal("incomplete options accepted")
	}
	if err := (&CachePolicyOptions{Profile: AcceptedCompletedCacheProfile}).Validate(); err == nil {
		t.Fatal("missing explicit limits accepted")
	}
}

func TestCachePolicyWriterFreezesDeclaration(t *testing.T) {
	id := ident()
	id.Core.CachePolicy = &CachePolicyOptions{Profile: AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 16, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16}}
	want := *id.Core.CachePolicy
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/policy", SegmentBytes: 400, Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	id.Core.CachePolicy.Profile = 77
	id.Core.CachePolicy.Limits.ReceivePending++
	// Later segment headers use the same frozen declaration, not the caller's
	// mutable object. This identity does not own any functional cache or stream.
	for request := uint64(1); request <= 12; request++ {
		w.Put(Record{Body: &SyncRec{Stage: "requested", Request: request, Syncing: true, Mono: time.Duration(request)}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.id.Core.CachePolicy == id.Core.CachePolicy || *w.id.Core.CachePolicy != want {
		t.Fatal("writer retained caller-owned policy settings")
	}
	records, err := ReadAll(fs, "/policy")
	if err != nil {
		t.Fatal(err)
	}
	segments := 0
	for _, record := range records {
		if segment, ok := record.Body.(*SegmentRec); ok {
			segments++
			if !reflect.DeepEqual(segment.Core.CachePolicy, &want) {
				t.Fatal("stored segment changed its profile")
			}
		}
	}
	if segments < 2 {
		t.Fatal("stored rotation was not exercised", segments)
	}
}
