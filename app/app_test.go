package app

import (
	"errors"
	"fmt"
	"testing"
)

func TestImportError(t *testing.T) {
	err := fmt.Errorf("import: %w", &ImportError{Step: "P4", Class: "ErrInvalidBody", Err: ErrInvalidBlock})
	if !errors.Is(err, ErrInvalidBlock) {
		t.Fatal("ImportError does not unwrap to its cause")
	}
	var ie *ImportError
	if !errors.As(err, &ie) || ie.Step != "P4" {
		t.Fatalf("errors.As: %v", ie)
	}
}

func TestHeadPath(t *testing.T) {
	// The names are the NEW_HEAD path values of the event vocabulary.
	for p, want := range map[HeadPath]string{SealedLocally: "sealed_locally", Imported: "imported", Synced: "synced", 9: "unknown"} { //wbft:unordered independent cases
		if got := p.String(); got != want {
			t.Errorf("%d: %q, want %q", p, got, want)
		}
	}
}

func TestInfoResponse(t *testing.T) {
	r := InfoResponse{AppMajors: []uint32{Major}, Features: []string{FeatureSendDecidedBlock}}
	if !r.SupportsMajor(Major) || r.SupportsMajor(Major+1) {
		t.Error("SupportsMajor")
	}
	if !r.HasFeature(FeatureSendDecidedBlock) || r.HasFeature(FeatureExecuteProposal) {
		t.Error("HasFeature")
	}
}
