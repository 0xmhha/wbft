package journal

import (
	"fmt"
	"github.com/0xmhha/wbft/codec/rlp"
	"math"
)

const SelectionSourceVersion uint64 = 1

// InputProbe identifies the source sequence actually read under one lane's
// original mutex (or the owning loop). State is empty, ready, or not_probed.
// Different lanes are never represented as one atomic snapshot.
type InputProbe struct {
	State          string
	Sequence, Mono uint64
}

// SelectionRec preserves one original next attempt and its actual dispatch.
// Step on select is the preceding completed step; selecting never proves the
// following step ran. Source is the original selected lane mutation sequence.
type SelectionRec struct {
	Version, Sequence, Selection, EngineRun, Step uint64
	Action, Lane                                  string
	Source                                        uint64
	Internal, App, Timer, Inbox                   InputProbe
	NextHeight                                    string
	Random, Choice                                uint64
	InputKind                                     string
	Input                                         []byte
	Mono, WallNs                                  uint64
	Unavailable                                   string
}
type selectionRLP struct {
	Format, JSeq uint64
	Source       SelectionRec
}

func validInputProbe(p InputProbe) bool {
	switch p.State {
	case "not_probed":
		return p.Sequence == 0 && p.Mono == 0
	case "empty", "ready":
		return p.Mono <= math.MaxInt64
	}
	return false
}
func emptyInputProbe(p InputProbe) bool { return p == (InputProbe{}) }
func validSelectionRec(r *SelectionRec) bool {
	if r.Version != SelectionSourceVersion || r.EngineRun == 0 || r.Mono > math.MaxInt64 || r.Random > 1 || r.Choice > 1 {
		return false
	}
	switch r.Unavailable {
	case "", "metadata_exhausted", "input_encoding", "lane_source_missing", "next_height_source", "manual_processing", "dequeue_unavailable", "dispatch_source_missing", "dispatch_deduplicated":
	default:
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	if r.Action == "select" {
		if r.Selection != r.Sequence || r.Step == 0 || !validInputProbe(r.Internal) || !validInputProbe(r.App) || !validInputProbe(r.Timer) || !validInputProbe(r.Inbox) {
			return false
		}
		switch r.NextHeight {
		case "not_probed", "disabled", "unsupported":
		default:
			return false
		}
		switch r.Lane {
		case "none":
			return r.Source == 0 && r.InputKind == "" && len(r.Input) == 0
		case "internal", "app", "timer", "peer", "next_height":
			return r.Unavailable != "" || r.Source > 0 && r.InputKind != "" && len(r.Input) > 0
		}
		return false
	}
	if r.Action != "dispatch" && r.Action != "discard" {
		return false
	}
	if !emptyInputProbe(r.Internal) || !emptyInputProbe(r.App) || !emptyInputProbe(r.Timer) || !emptyInputProbe(r.Inbox) || r.NextHeight != "" || r.Random != 0 || r.Choice != 0 || r.Source != 0 || r.Lane != "" {
		return false
	}
	if r.Action == "discard" && (r.Step != 0 || r.Unavailable == "") || r.Action == "dispatch" && r.Step == 0 {
		return false
	}
	return r.Unavailable != "" || r.Selection > 0 && r.InputKind != "" && len(r.Input) > 0
}
func encodeSelectionRec(r *SelectionRec, jseq uint64) ([]byte, error) {
	if !validSelectionRec(r) {
		return nil, fmt.Errorf("journal: invalid input selection source")
	}
	return rlp.Encode(&selectionRLP{Format: Format, JSeq: jseq, Source: *r})
}
func decodeSelectionRec(body []byte) (Record, error) {
	var w selectionRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: input selection: %v", ErrRecord, err)
	}
	if w.Format != Format || !validSelectionRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid input selection source", ErrRecord)
	}
	return Record{Kind: KindSelection, JSeq: w.JSeq, Body: &w.Source}, nil
}
