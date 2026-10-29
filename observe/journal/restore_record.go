package journal

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

const RestoreSourceVersion uint64 = 1

// WALReadRef identifies an original observed read, not a previous WAL writer.
type WALReadRef struct {
	Namespace     string
	Log, Sequence uint64
}

type RestoreOwn struct {
	Code    uint64
	Payload []byte
}

// RestoreAttempt retains the actual invocation result. Timers are canonical
// output encodings; they describe computed timers, not executed timer arms.
type RestoreAttempt struct {
	Inputs, Fed, Steps, Failed, LastPartial uint64
	Snapshot                                types.Hash
	Generations                             []uint64
	Own                                     []RestoreOwn
	Timers                                  [][]byte
}

// RestoreRec joins the original read to actual planning, replay attempts and
// installation. Input indexes and Boundary are one-based; zero means absent.
// This diagnostic does not authenticate roots or prove private signer/app state.
type RestoreRec struct {
	Version, EngineRun         uint64
	Read                       WALReadRef
	From                       string
	Boundary                   uint64
	Inputs                     []uint64
	PlanFailed                 uint64
	Attempts                   []RestoreAttempt
	Installed, Replayed, Steps uint64
	Snapshot                   types.Hash
	Generations                []uint64
	Own                        []RestoreOwn
	Mono, WallNs               uint64
	Unavailable                string
}

type restoreRLP struct {
	Format, JSeq uint64
	Source       RestoreRec
}

func validRestoreRec(r *RestoreRec) bool {
	if r.Version != RestoreSourceVersion || r.EngineRun == 0 || r.Mono > math.MaxInt64 || !canonicalContextNumber(r.From) || r.PlanFailed > 1 || r.Installed > 1 || r.Replayed > 1 || len(r.Attempts) > 2 {
		return false
	}
	switch r.Unavailable {
	case "", "read_source_missing", "source_unavailable", "inspection_limits_required", "frame_limit", "byte_limit", "snapshot_encoding", "output_encoding", "replay_disabled", "wal_missing", "next_height", "validator_start_profile":
	default:
		return false
	}
	if r.Unavailable == "" && (r.Read.Namespace == "" || r.Read.Log == 0 || r.Read.Sequence == 0) {
		return false
	}
	if r.Unavailable == "" && r.Installed == 1 && len(r.Generations) != 4 {
		return false
	}
	var last uint64
	for _, o := range r.Own {
		if o.Code == 0 || o.Code <= last || len(o.Payload) == 0 {
			return false
		}
		last = o.Code
	}
	last = 0
	for _, i := range r.Inputs {
		if i == 0 || i <= last || i <= r.Boundary {
			return false
		}
		last = i
	}
	for _, a := range r.Attempts {
		if a.Failed > 1 || a.LastPartial > 1 || a.Fed > a.Inputs || a.Inputs > uint64(len(r.Inputs)) || len(a.Generations) != 4 || len(a.Timers) != 4 {
			return false
		}
		last = 0
		for _, o := range a.Own {
			if o.Code == 0 || o.Code <= last || len(o.Payload) == 0 {
				return false
			}
			last = o.Code
		}
	}
	return true
}
func encodeRestoreRec(r *RestoreRec, seq uint64) ([]byte, error) {
	if !validRestoreRec(r) {
		return nil, fmt.Errorf("journal: invalid restore source")
	}
	return rlp.Encode(&restoreRLP{Format, seq, *r})
}
func decodeRestoreRec(b []byte) (Record, error) {
	var w restoreRLP
	if err := rlp.DecodeStrict(b, &w); err != nil || w.Format != Format || !validRestoreRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid restore source", ErrRecord)
	}
	return Record{Kind: KindRestore, JSeq: w.JSeq, Body: &w.Source}, nil
}

type restoreSeal struct {
	Source          types.Address
	Sequence, Round string
	Digest          types.Hash
	Seal            []byte
}

// RestoreSnapshotDigest covers the complete public snapshot, including ordered
// extra seals and authority key presence. It does not serialize private state.
func RestoreSnapshotDigest(s *consensus.Snapshot) (types.Hash, error) {
	if s == nil || s.Backlog < 0 {
		return types.Hash{}, fmt.Errorf("journal: missing restore snapshot")
	}
	context, err := InboxSnapshotDigest(s)
	if err != nil {
		return types.Hash{}, err
	}
	w := struct {
		Domain              string
		Context             types.Hash
		Proposer            types.Address
		IsProposer, Backlog uint64
		Prepare, Commit     []restoreSeal
	}{Domain: "wbft/restore-snapshot/v1", Context: context, Proposer: s.Proposer, IsProposer: boolUint(s.IsProposer), Backlog: uint64(s.Backlog)}
	for _, e := range s.ExtraPrepare {
		w.Prepare = append(w.Prepare, restoreSeal{e.Source, e.View.Sequence.String(), e.View.Round.String(), e.Digest, e.Seal})
	}
	for _, e := range s.ExtraCommit {
		w.Commit = append(w.Commit, restoreSeal{e.Source, e.View.Sequence.String(), e.View.Round.String(), e.Digest, e.Seal})
	}
	b, err := rlp.Encode(&w)
	if err != nil {
		return types.Hash{}, err
	}
	return sha256.Sum256(b), nil
}
