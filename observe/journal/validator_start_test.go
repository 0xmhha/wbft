package journal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
)

func TestValidatorStartRestoreUnavailableRoundtrip(t *testing.T) {
	r := restoreRecordFixture()
	r.Unavailable = "validator_start_profile"
	r.Generations = nil
	raw, err := encodeBody(Record{Body: r}, 1)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeBody(KindRestore, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := back.Body.(*RestoreRec)
	if !ok || got.Unavailable != "validator_start_profile" || len(got.Generations) != 0 {
		t.Fatal("unsupported profile became a supported four-counter restore")
	}
	again, err := encodeBody(back, 1)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("unavailable source changed", err)
	}
}

func TestValidatorStartTimerCancelMetadataRoundtrip(t *testing.T) {
	r := &TimerRec{Sequence: 1, EngineRun: 1, Step: 1, Source: "core", Action: "cancel", Kinds: []uint64{0, 1, 2, 3, 4}}
	raw, err := encodeTimerRec(r, 1)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeTimerRec(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeTimerRec(back.Body.(*TimerRec), 1)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("fifth local timer metadata changed", err)
	}
	r.Kinds = []uint64{5}
	if _, err := encodeTimerRec(r, 1); err == nil {
		t.Fatal("unknown timer kind accepted")
	}
}

func TestValidatorStartIndependentRestoreCannotSkipUnknownProfile(t *testing.T) {
	for _, format := range []uint8{1, 5} {
		fs := fsys.NewMem()
		log, _, err := wal.Open(fs, "/new-reader-model", wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		// A fresh capture supplies opaque unsupported-profile metadata. It is
		// never fed to a live runner or used to alter existing stored frames.
		if _, err := log.AppendSync(wal.Record{Format: format, Kind: 1, Body: []byte("opaque-model")}); err != nil {
			t.Fatal(err)
		}
		_, _, source, err := log.ReadAllObserved("reader-model", wal.ReadSourceLimits{Frames: 8, Bytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		read := &WALReadRec{Source: source}
		id := ident()
		id.Run = "reader-model"
		if format == 1 {
			id.Core.Improvements = uint64(consensus.ImprovementSet(0).With(consensus.DeferValidatorStart))
		} else {
			id.Core.Improvements = 0
		}
		restore := restoreRecordFixture()
		restore.Read = WALReadRef{source.Namespace, source.Log, source.Sequence}
		// No producer unavailable hint and a legacy-shaped four-counter
		// envelope: the reader must independently refuse a success verdict.
		restore.Steps = 0
		records := []Record{{Body: &SegmentRec{Identity: id}}, {Body: read}, {Body: restore}}
		report, err := CheckRestoreSources(records, CoreSourceLimits{Records: 100, Runs: 8, Steps: 32, Environments: 32, Outputs: 64, Bytes: 1 << 20})
		if err != nil || report.Status != "unavailable" || report.Reason != "validator_start_profile" {
			t.Fatal("unsupported original prefix became consistent", format, report, err)
		}
		_, err = independentRestorePlan(read, "10", coreSourceWriter{improvements: id.Core.Improvements})
		if !errors.Is(err, errRestoreValidatorStart) {
			t.Fatal("independent old planner skipped selected profile", err)
		}
	}
}
