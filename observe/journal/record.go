package journal

import (
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// Format is the format number of journal records: the format byte of the
// frame and the first element of every record body.
const Format = 1

// Kind is the kind of a journal record.
type Kind uint8

// Record kinds.
const (
	KindSegment    Kind = 1 // first record of every segment: who wrote it
	KindPeer       Kind = 2 // a peer's consensus stream was attached or closed
	KindMsg        Kind = 3 // a consensus message received or sent
	KindOutcome    Kind = 4 // what the node did with a received message
	KindSuppressed Kind = 5 // a send suppressed by the recent cache
	KindStep       Kind = 6 // one input of the core and the digest of its outputs
	KindGap        Kind = 7 // records dropped while the queue was full
)

func (k Kind) String() string {
	switch k {
	case KindSegment:
		return "segment"
	case KindPeer:
		return "peer"
	case KindMsg:
		return "msg"
	case KindOutcome:
		return "outcome"
	case KindSuppressed:
		return "suppressed"
	case KindStep:
		return "step"
	case KindGap:
		return "gap"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Record is one journal record. Body is one of *SegmentRec, *PeerRec,
// *MsgRec, *OutcomeRec, *SuppressedRec, *StepRec, *GapRec. JSeq is assigned
// by the writer: it increases by one per written record within a run.
type Record struct {
	Kind Kind
	JSeq uint64
	Body any
}

// Identity is what a segment record says about the writing node and its
// configuration.
type Identity struct {
	Self         types.Address
	NodeID       []byte
	BLSPublicKey []byte
	Run          string
	Commit       string // wbft source revision
	ChainID      *big.Int
	GenesisHash  types.Hash
	Mode         string // "embedded" or "standalone"
	WireOffset   uint64
	ConfigDigest types.Hash
	// Core is the configuration that rebuilds the consensus core.
	Core CoreOptions
}

// CoreOptions is the consensus.Options of the journaled core in a portable
// form: the chain configuration as its JSON text (types.ParseChainConfig).
type CoreOptions struct {
	ChainConfig  []byte
	Self         types.Address
	Improvements uint64
	BacklogLimit uint64
	Profile      string
}

// SegmentRec is the first record of a segment.
type SegmentRec struct {
	Identity
	EngineRun uint64
}

// PeerRec reports a peer's consensus stream.
type PeerRec struct {
	PeerIdx uint32
	Addr    types.Address
	NodeID  []byte
	Remote  string
	Event   string // "attached" or "closed"
	Reason  string
}

// Directions of MsgRec.
const (
	In  = "in"
	Out = "out"
)

// MsgRec is one consensus message on the wire.
type MsgRec struct {
	Dir      string
	PeerIdx  uint32
	Mono     time.Duration
	WallNs   int64
	Code     uint64
	WireCode uint64
	Payload  []byte // not copied; the caller must not reuse the slice
	DedupKey types.Hash
	Offer    string          // In only: queued, queue_full, frame_ignore, frame_disconnect
	Cause    event.SendCause // Out only
	RelayOf  uint64          // Out only: jseq of the received message, 0 if none
	Write    string          // Out only: ok, error, not_attached
}

// OutcomeRec is what the node did with a received message; the values are
// those of MSG_OUTCOME.
type OutcomeRec struct {
	Of         uint64 // jseq of the "in" msg record, 0 if unknown
	Code       uint64
	Peer       types.Address
	DedupKey   types.Hash
	Outcome    event.OutcomeClass
	Check      string
	Row        int64 // -1: none
	Reason     string
	ErrorClass string
	Via        string
	Step       uint64 // core step that handled it, 0 if none
}

// SuppressedRec is a send the recent cache suppressed.
type SuppressedRec struct {
	PeerIdx  uint32
	DedupKey types.Hash
	Cause    event.SendCause
	Reason   string
}

// StepRec is one input of the core.
type StepRec struct {
	EngineRun uint64
	Step      uint64
	Mono      time.Duration
	WallNs    int64
	// InputKind and Input are the input as consensus/inputlog encodes it.
	InputKind string
	Input     []byte
	// Via tells where the input came from: internal, app, timer, peer, or
	// wal for a write-ahead log replay.
	Via string
	// HeadNumber and HeadHash are the head the core reads (Env.Head) while
	// it handles the input.
	HeadNumber types.Height
	HeadHash   types.Hash
	// Env holds the Env answers that depend on the application
	// (ValidateProposal, IsBadBlock), encoded by inputlog.EncodeEnv, in call
	// order.
	Env          [][]byte
	ValsetDigest types.Hash
	OutDigest    types.Hash
	// TimerGens, on a start step, are the timer generations the new core
	// continues (from a write-ahead log replay); empty means zero.
	TimerGens []uint64
}

// GapRec reports records dropped while the queue was full.
type GapRec struct {
	Dropped   uint64
	ByKind    []KindCount
	FirstMono time.Duration
	LastMono  time.Duration
}

// KindCount is a number of records of one kind.
type KindCount struct {
	Kind  uint64
	Count uint64
}

// Body encodings: [format, jseq, fields...] per kind.

type segmentRLP struct {
	Format       uint64
	JSeq         uint64
	Self         types.Address
	NodeID       []byte
	BLSPublicKey []byte
	Run          string
	Commit       string
	ChainID      *big.Int
	GenesisHash  types.Hash
	Mode         string
	WireOffset   uint64
	ConfigDigest types.Hash
	ChainConfig  []byte
	CoreSelf     types.Address
	Improvements uint64
	BacklogLimit uint64
	Profile      string
	EngineRun    uint64
}

type peerRLP struct {
	Format  uint64
	JSeq    uint64
	PeerIdx uint64
	Addr    types.Address
	NodeID  []byte
	Remote  string
	Event   string
	Reason  string
}

type msgRLP struct {
	Format   uint64
	JSeq     uint64
	Dir      string
	PeerIdx  uint64
	Mono     uint64
	WallNs   uint64
	Code     uint64
	WireCode uint64
	Payload  []byte
	DedupKey types.Hash
	Offer    string
	Cause    string
	RelayOf  uint64
	Write    string
}

type outcomeRLP struct {
	Format     uint64
	JSeq       uint64
	Of         uint64
	Code       uint64
	Peer       types.Address
	DedupKey   types.Hash
	Outcome    string
	Check      string
	Row        uint64
	Reason     string
	ErrorClass string
	Via        string
	Step       uint64
}

type suppressedRLP struct {
	Format   uint64
	JSeq     uint64
	PeerIdx  uint64
	DedupKey types.Hash
	Cause    string
	Reason   string
}

type stepRLP struct {
	Format       uint64
	JSeq         uint64
	EngineRun    uint64
	Step         uint64
	Mono         uint64
	WallNs       uint64
	InputKind    string
	Input        []byte
	Via          string
	HeadNumber   *big.Int
	HeadHash     types.Hash
	Env          [][]byte
	ValsetDigest types.Hash
	OutDigest    types.Hash
	TimerGens    []uint64
}

type gapRLP struct {
	Format    uint64
	JSeq      uint64
	Dropped   uint64
	ByKind    []KindCount
	FirstMono uint64
	LastMono  uint64
}

func bytesOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func bigOrZero(b *big.Int) *big.Int {
	if b == nil {
		return new(big.Int)
	}
	return b
}

// encodeBody returns the body of r with jseq.
func encodeBody(r Record, jseq uint64) ([]byte, error) {
	switch b := r.Body.(type) {
	case *SegmentRec:
		return rlp.Encode(&segmentRLP{Format: Format, JSeq: jseq, Self: b.Self, NodeID: bytesOrEmpty(b.NodeID),
			BLSPublicKey: bytesOrEmpty(b.BLSPublicKey), Run: b.Run, Commit: b.Commit, ChainID: bigOrZero(b.ChainID),
			GenesisHash: b.GenesisHash, Mode: b.Mode, WireOffset: b.WireOffset, ConfigDigest: b.ConfigDigest,
			ChainConfig: bytesOrEmpty(b.Core.ChainConfig), CoreSelf: b.Core.Self, Improvements: b.Core.Improvements,
			BacklogLimit: b.Core.BacklogLimit, Profile: b.Core.Profile, EngineRun: b.EngineRun})
	case *PeerRec:
		return rlp.Encode(&peerRLP{Format: Format, JSeq: jseq, PeerIdx: uint64(b.PeerIdx), Addr: b.Addr, NodeID: bytesOrEmpty(b.NodeID),
			Remote: b.Remote, Event: b.Event, Reason: b.Reason})
	case *MsgRec:
		return rlp.Encode(&msgRLP{Format: Format, JSeq: jseq, Dir: b.Dir, PeerIdx: uint64(b.PeerIdx), Mono: uint64(int64(b.Mono)),
			WallNs: uint64(b.WallNs), Code: b.Code, WireCode: b.WireCode, Payload: bytesOrEmpty(b.Payload), DedupKey: b.DedupKey,
			Offer: b.Offer, Cause: string(b.Cause), RelayOf: b.RelayOf, Write: b.Write})
	case *OutcomeRec:
		return rlp.Encode(&outcomeRLP{Format: Format, JSeq: jseq, Of: b.Of, Code: b.Code, Peer: b.Peer, DedupKey: b.DedupKey,
			Outcome: string(b.Outcome), Check: b.Check, Row: uint64(b.Row + 1), Reason: b.Reason, ErrorClass: b.ErrorClass,
			Via: b.Via, Step: b.Step})
	case *SuppressedRec:
		return rlp.Encode(&suppressedRLP{Format: Format, JSeq: jseq, PeerIdx: uint64(b.PeerIdx), DedupKey: b.DedupKey,
			Cause: string(b.Cause), Reason: b.Reason})
	case *StepRec:
		env := b.Env
		if env == nil {
			env = [][]byte{}
		}
		gens := b.TimerGens
		if gens == nil {
			gens = []uint64{}
		}
		return rlp.Encode(&stepRLP{Format: Format, JSeq: jseq, EngineRun: b.EngineRun, Step: b.Step, Mono: uint64(int64(b.Mono)),
			WallNs: uint64(b.WallNs), InputKind: b.InputKind, Input: bytesOrEmpty(b.Input), Via: b.Via,
			HeadNumber: heightBig(b.HeadNumber), HeadHash: b.HeadHash, Env: env, ValsetDigest: b.ValsetDigest, OutDigest: b.OutDigest, TimerGens: gens})
	case *GapRec:
		bk := b.ByKind
		if bk == nil {
			bk = []KindCount{}
		}
		return rlp.Encode(&gapRLP{Format: Format, JSeq: jseq, Dropped: b.Dropped, ByKind: bk,
			FirstMono: uint64(int64(b.FirstMono)), LastMono: uint64(int64(b.LastMono))})
	}
	return nil, fmt.Errorf("journal: unknown record body %T", r.Body)
}

func heightBig(h types.Height) *big.Int { return h.Big() }

// ErrRecord reports a record that does not decode.
var ErrRecord = fmt.Errorf("journal: malformed record")

// decodeBody decodes the body of a record of kind k.
func decodeBody(k Kind, body []byte) (Record, error) {
	fail := func(err error) (Record, error) { return Record{}, fmt.Errorf("%w: %s: %v", ErrRecord, k, err) }
	check := func(f uint64) error {
		if f != Format {
			return fmt.Errorf("format %d", f)
		}
		return nil
	}
	switch k {
	case KindSegment:
		var w segmentRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &SegmentRec{EngineRun: w.EngineRun, Identity: Identity{
			Self: w.Self, NodeID: w.NodeID, BLSPublicKey: w.BLSPublicKey, Run: w.Run, Commit: w.Commit, ChainID: w.ChainID,
			GenesisHash: w.GenesisHash, Mode: w.Mode, WireOffset: w.WireOffset, ConfigDigest: w.ConfigDigest,
			Core: CoreOptions{ChainConfig: w.ChainConfig, Self: w.CoreSelf, Improvements: w.Improvements, BacklogLimit: w.BacklogLimit, Profile: w.Profile},
		}}}, nil
	case KindPeer:
		var w peerRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &PeerRec{PeerIdx: uint32(w.PeerIdx), Addr: w.Addr, NodeID: w.NodeID, Remote: w.Remote, Event: w.Event, Reason: w.Reason}}, nil
	case KindMsg:
		var w msgRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &MsgRec{Dir: w.Dir, PeerIdx: uint32(w.PeerIdx), Mono: time.Duration(int64(w.Mono)),
			WallNs: int64(w.WallNs), Code: w.Code, WireCode: w.WireCode, Payload: w.Payload, DedupKey: w.DedupKey, Offer: w.Offer,
			Cause: event.SendCause(w.Cause), RelayOf: w.RelayOf, Write: w.Write}}, nil
	case KindOutcome:
		var w outcomeRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &OutcomeRec{Of: w.Of, Code: w.Code, Peer: w.Peer, DedupKey: w.DedupKey,
			Outcome: event.OutcomeClass(w.Outcome), Check: w.Check, Row: int64(w.Row) - 1, Reason: w.Reason, ErrorClass: w.ErrorClass,
			Via: w.Via, Step: w.Step}}, nil
	case KindSuppressed:
		var w suppressedRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &SuppressedRec{PeerIdx: uint32(w.PeerIdx), DedupKey: w.DedupKey, Cause: event.SendCause(w.Cause), Reason: w.Reason}}, nil
	case KindStep:
		var w stepRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		hn, err := types.HeightFromBig(bigOrZero(w.HeadNumber))
		if err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &StepRec{EngineRun: w.EngineRun, Step: w.Step, Mono: time.Duration(int64(w.Mono)),
			WallNs: int64(w.WallNs), InputKind: w.InputKind, Input: w.Input, Via: w.Via, HeadNumber: hn, HeadHash: w.HeadHash,
			Env: w.Env, ValsetDigest: w.ValsetDigest, OutDigest: w.OutDigest, TimerGens: w.TimerGens}}, nil
	case KindGap:
		var w gapRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &GapRec{Dropped: w.Dropped, ByKind: w.ByKind, FirstMono: time.Duration(int64(w.FirstMono)), LastMono: time.Duration(int64(w.LastMono))}}, nil
	}
	return Record{}, fmt.Errorf("%w: unknown kind %d", ErrRecord, uint8(k))
}

// kindOf returns the kind of a record body.
func kindOf(body any) (Kind, bool) {
	switch body.(type) {
	case *SegmentRec:
		return KindSegment, true
	case *PeerRec:
		return KindPeer, true
	case *MsgRec:
		return KindMsg, true
	case *OutcomeRec:
		return KindOutcome, true
	case *SuppressedRec:
		return KindSuppressed, true
	case *StepRec:
		return KindStep, true
	case *GapRec:
		return KindGap, true
	}
	return 0, false
}

// size estimates the queue bytes of a record.
func size(r Record) int64 {
	switch b := r.Body.(type) {
	case *MsgRec:
		return int64(len(b.Payload)) + 128
	case *StepRec:
		n := int64(len(b.Input)) + 160
		for _, e := range b.Env {
			n += int64(len(e))
		}
		return n
	case *SegmentRec:
		return int64(len(b.Core.ChainConfig)) + 256
	}
	return 96
}
