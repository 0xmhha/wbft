package journal

import (
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func observationOptions(t *testing.T) *ObservationOptions {
	t.Helper()
	full := new(big.Int).Lsh(big.NewInt(1), 128)
	o, err := NewObservationOptions(window.Config{ChainID: full, GenesisHash: types.Hash{1}, Activation: types.MustHeightFromBig(full),
		Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20,
		CheckpointBytes: 2 << 20, AddressRows: 32}, types.MustHeightFromBig(full), 128, 128)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestObservationProfileFullWidthRoundTripAndCapabilities(t *testing.T) {
	id := ident()
	id.Core.Observation = observationOptions(t)
	id.ChainID, _ = new(big.Int).SetString(id.Core.Observation.ChainID, 10)
	id.GenesisHash = id.Core.Observation.GenesisHash
	id.Core.ChainConfig = []byte(`{"chainId":` + id.ChainID.String() + `,"anzeon":{"wbft":{}}}`)
	for _, profile := range []uint64{RecentObservationProfile, 77} {
		id.Core.Observation.Profile = profile
		raw, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		record, err := decodeBody(KindSegment, raw)
		if err != nil {
			t.Fatal(err)
		}
		got := record.Body.(*SegmentRec).Core
		if !reflect.DeepEqual(got.Observation, id.Core.Observation) {
			t.Fatal("observation policy changed in the segment")
		}
		encoded, err := json.Marshal(got)
		if err != nil || !bytes.Contains(encoded, []byte(`"retention":"`+id.ChainID.String()+`"`)) {
			t.Fatal("full-width retention lost in JSON", err)
		}
		_, err = got.Configuration()
		if (profile == RecentObservationProfile) != (err == nil) {
			t.Fatal("profile declaration and replay capability differ", profile, err)
		}
	}
}

func TestObservationProfileRejectsChangedClosedMetadata(t *testing.T) {
	want := observationOptions(t)
	for _, change := range []func(*ObservationOptions){
		func(o *ObservationOptions) { o.Retention = "0" },
		func(o *ObservationOptions) { o.Activation = "0" + o.Activation },
		func(o *ObservationOptions) { o.ChainID = "-1" },
		func(o *ObservationOptions) { o.PolicyDigest[0] ^= 1 },
		func(o *ObservationOptions) { o.ReplayHeaders = 0 },
		func(o *ObservationOptions) { o.HistoryWalk = 0 },
		func(o *ObservationOptions) { o.Codec.Proofs = 0 },
		func(o *ObservationOptions) { o.Checkpoint = make([]byte, o.CheckpointBytes+1) },
	} {
		copy := *want
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("changed closed policy metadata accepted")
		}
	}
	if want.ValidateIdentity(big.NewInt(1), want.GenesisHash) == nil || want.ValidateIdentity(new(big.Int).Lsh(big.NewInt(1), 128), types.Hash{2}) == nil {
		t.Fatal("different recorded chain identity accepted")
	}
}

func TestObservationWriterFreezesProfileAndCheckpoint(t *testing.T) {
	id := ident()
	id.Core.Observation = observationOptions(t)
	id.Core.Observation.Checkpoint = []byte("closed checkpoint metadata")
	id.ChainID, _ = new(big.Int).SetString(id.Core.Observation.ChainID, 10)
	id.GenesisHash = id.Core.Observation.GenesisHash
	want := *id.Core.Observation
	want.Checkpoint = bytes.Clone(want.Checkpoint)
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/observation", SegmentBytes: 400, Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	id.Core.Observation.Profile = 77
	id.Core.Observation.Checkpoint[0] ^= 1
	for request := uint64(1); request <= 12; request++ {
		w.Put(Record{Body: &SyncRec{Stage: "requested", Request: request, Syncing: true, Mono: time.Duration(request)}})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/observation")
	if err != nil {
		t.Fatal(err)
	}
	segments := 0
	for _, record := range records {
		if segment, ok := record.Body.(*SegmentRec); ok {
			segments++
			if !reflect.DeepEqual(segment.Core.Observation, &want) {
				t.Fatal("caller changed a later segment's frozen observation policy")
			}
		}
	}
	if segments < 2 {
		t.Fatal("segment rotation was not exercised")
	}
}
