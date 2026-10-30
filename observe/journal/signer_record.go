package journal

import (
	"errors"
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/types"
)

const SignerCallSourceVersion uint64 = 1

// ErrSignerSourceUnsupported preserves readable future profile declarations
// without labeling an unsupported signing context as malformed data.
var ErrSignerSourceUnsupported = errors.New("journal: unsupported signer source profile")

type SignerRec struct {
	Source       privval.Source
	Mono, WallNs uint64
}
type signerRLP struct {
	Format, JSeq uint64
	Source       SignerRec
}

// SignerCallRec retains one actual runner call and its own-message WAL result.
// WAL identifies the earlier observed read of the same Log object, not a proof
// of its earlier writer or of physical durability. Position is one actual frame.
type SignerCallRec struct {
	Version, EngineRun, Step, Output        uint64
	Source                                  privval.SourceRef
	RequestCode                             uint64
	Request, SealData                       []byte
	BadBlockReleased                        uint64
	Signature, Seal                         []byte
	Reused                                  uint64
	Result                                  string
	WAL                                     WALReadRef
	WALPresent, WALWritten, Segment, Offset uint64
	Payload                                 []byte
	Mono, WallNs                            uint64
	Unavailable                             string
}
type signerCallRLP struct {
	Format, JSeq uint64
	Source       SignerCallRec
}

func validSignerCall(r *SignerCallRec) bool {
	if r.Version != SignerCallSourceVersion || r.EngineRun == 0 || r.Step == 0 || r.Output == 0 || r.BadBlockReleased > 1 || r.Reused > 1 || r.WALPresent > 1 || r.WALWritten > 1 || r.Mono > math.MaxInt64 || r.Offset > math.MaxInt64 {
		return false
	}
	switch r.Result {
	case "sent", "refused", "signer_error", "outbound_error", "wal_error", "signer_missing":
	default:
		return false
	}
	switch r.Unavailable {
	case "", "source_missing", "request_encoding", "wal_missing", "wal_read_missing", "payload_encoding":
	default:
		return false
	}
	if r.Unavailable == "" && (r.Source.Namespace == "" || r.Source.Signer == 0 || r.Source.Sequence == 0) {
		return false
	}
	if r.WALWritten == 1 && (r.WALPresent == 0 || len(r.Payload) == 0) {
		return false
	}
	return true
}
func encodeSignerRec(r *SignerRec, jseq uint64) ([]byte, error) {
	if r.Mono > math.MaxInt64 || privval.ValidateSource(r.Source) != nil {
		return nil, fmt.Errorf("journal: invalid signer source")
	}
	return rlp.Encode(&signerRLP{Format, jseq, *r})
}
func decodeSignerRec(b []byte) (Record, error) {
	var w signerRLP
	if err := rlp.DecodeStrict(b, &w); err != nil || w.Format != Format || w.Source.Mono > math.MaxInt64 {
		return Record{}, fmt.Errorf("%w: invalid signer source", ErrRecord)
	}
	if w.Source.Source.Version != privval.SourceVersion && w.Source.Source.Version != privval.DomainSourceVersion {
		return Record{}, ErrSignerSourceUnsupported
	}
	if err := privval.ValidateSource(w.Source.Source); err != nil {
		if errors.Is(err, types.ErrRoundChangeDomainVersion) {
			return Record{}, fmt.Errorf("%w: %w", ErrSignerSourceUnsupported, err)
		}
		return Record{}, fmt.Errorf("%w: invalid signer source", ErrRecord)
	}
	return Record{Kind: KindSigner, JSeq: w.JSeq, Body: &w.Source}, nil
}
func encodeSignerCallRec(r *SignerCallRec, jseq uint64) ([]byte, error) {
	if !validSignerCall(r) {
		return nil, fmt.Errorf("journal: invalid signer call")
	}
	return rlp.Encode(&signerCallRLP{Format, jseq, *r})
}
func decodeSignerCallRec(b []byte) (Record, error) {
	var w signerCallRLP
	if err := rlp.DecodeStrict(b, &w); err != nil || w.Format != Format || !validSignerCall(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid signer call", ErrRecord)
	}
	return Record{Kind: KindSignerCall, JSeq: w.JSeq, Body: &w.Source}, nil
}
