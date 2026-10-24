package journal

import (
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
)

const InternalSourceVersion uint64 = 1

// InternalRec retains original internal-queue appends through selection and
// actual dispatch. Output is the one-based independently recomputable core
// output coordinate. This diagnostic record proves neither signer state nor a
// closed runner schedule. The v1 wire value is [format, journal-sequence, source].
type InternalRec struct {
	Version, Sequence, Request  uint64
	EngineRun, Step, Output     uint64
	Action, Origin, InputKind   string
	Input                       []byte
	Before, After, Mono, WallNs uint64
	Unavailable                 string
}

type internalRLP struct {
	Format, JSeq uint64
	Source       InternalRec
}

func validInternalRec(r *InternalRec) bool {
	if r.Version != InternalSourceVersion || r.Mono > math.MaxInt64 || r.EngineRun == 0 {
		return false
	}
	switch r.Unavailable {
	case "", "metadata_exhausted", "input_encoding", "replay_prefix", "signer_state", "dispatch_source_missing", "dispatch_deduplicated":
	default:
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	switch r.Action {
	case "reset", "clear":
		return r.Request == 0 && r.Output == 0 && r.Origin == "" && r.InputKind == "" && len(r.Input) == 0 && r.After == 0 && (r.Action == "reset" && r.Step == 0 || r.Action == "clear" && r.Step > 0)
	case "append":
		if r.Request != r.Sequence || r.Before == math.MaxUint64 || r.After != r.Before+1 {
			return false
		}
		switch r.Origin {
		case "schedule", "own", "signer_missing", "refusal", "outbound":
			if r.Step == 0 || r.Output == 0 {
				return false
			}
		case "replay":
			if r.Step != 0 || r.Output != 0 || r.Unavailable == "" {
				return false
			}
		default:
			return false
		}
	case "pop":
		if r.Step != 0 || r.Output != 0 || r.Origin != "" || r.Before == 0 || r.After != r.Before-1 {
			return false
		}
	case "dispatch", "discard":
		if r.Output != 0 || r.Origin != "" || r.Before != 0 || r.After != 0 || (r.Action == "dispatch" && r.Step == 0) || (r.Action == "discard" && (r.Step != 0 || r.Unavailable == "")) {
			return false
		}
	default:
		return false
	}
	return r.Unavailable != "" || r.Request > 0 && r.InputKind != "" && len(r.Input) > 0
}

func encodeInternalRec(r *InternalRec, jseq uint64) ([]byte, error) {
	if !validInternalRec(r) {
		return nil, fmt.Errorf("journal: invalid internal source")
	}
	return rlp.Encode(&internalRLP{Format: Format, JSeq: jseq, Source: *r})
}

func decodeInternalRec(body []byte) (Record, error) {
	var w internalRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return Record{}, fmt.Errorf("%w: internal source: %v", ErrRecord, err)
	}
	if w.Format != Format || !validInternalRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid internal source", ErrRecord)
	}
	return Record{Kind: KindInternal, JSeq: w.JSeq, Body: &w.Source}, nil
}
