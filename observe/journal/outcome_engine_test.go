package journal

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

func TestOutcomeEngineRunCompatibility(t *testing.T) {
	// The pre-generation outcome format includes AtOffer but has no
	// engine field. Its exact bytes must remain valid and reproducible.
	legacy, err := hex.DecodeString("f8530102801394aa00000000000000000000000000000000000000a0abababababababababababababababababababababababababababababababab864143434550548750524f434553530480808473656c660780")
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeBody(KindOutcome, legacy)
	if err != nil {
		t.Fatal(err)
	}
	outcome := record.Body.(*OutcomeRec)
	if outcome.EngineRun != 0 || outcome.Step != 7 || outcome.Via != "self" || outcome.AtOffer {
		t.Fatalf("legacy record invented generation: %+v", outcome)
	}
	encoded, err := encodeBody(record, record.JSeq)
	if err != nil || !bytes.Equal(encoded, legacy) {
		t.Fatalf("legacy bytes changed: %x, error %v", encoded, err)
	}
	for _, generation := range []uint64{1, 2, math.MaxUint64} {
		outcome.EngineRun = generation
		encoded, err := encodeBody(record, record.JSeq)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeBody(KindOutcome, encoded)
		if err != nil {
			t.Fatal(err)
		}
		got := decoded.Body.(*OutcomeRec)
		if *got != *outcome || decoded.JSeq != record.JSeq {
			t.Fatalf("generation identity changed: %+v, want %+v", got, outcome)
		}
	}
}
