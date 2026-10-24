package journal

import (
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Format is the format number of journal records: the format byte of the
// frame and the first element of every record body.
const Format = 1

// Kind is the kind of a journal record.
type Kind uint8

// Record kinds.
const (
	KindSegment         Kind = 1  // first record of every segment: who wrote it
	KindPeer            Kind = 2  // a peer's consensus stream was attached or closed
	KindMsg             Kind = 3  // a consensus message received or sent
	KindOutcome         Kind = 4  // what the node did with a received message
	KindSuppressed      Kind = 5  // a send suppressed by the recent cache
	KindStep            Kind = 6  // one input of the core and the digest of its outputs
	KindGap             Kind = 7  // records dropped while the queue was full
	KindTimer           Kind = 8  // measured scheduler mutation and queue timing
	KindCache           Kind = 9  // measured cache mutation and empty-instance declaration
	KindSync            Kind = 10 // submitted and processed application sync controls
	KindWriteCache      Kind = 11 // actual accepted/completed write-ledger observations
	KindReceiveCache    Kind = 12 // actual accepted-input checking-ledger observations
	KindSession         Kind = 13 // original stream observations and functional endings
	KindCoreStep        Kind = 14 // detached actual live core execution sources
	KindAppQueue        Kind = 15 // detached application-input queue mutex mutations
	KindFinalize        Kind = 16 // detached commit queue and application call boundaries
	KindInbox           Kind = 17 // detached inbox queue and slot sources
	KindInternal        Kind = 18 // detached internal queue source and dispatch boundaries
	KindSelection       Kind = 19 // original conditional probes and selected input dispatch
	KindReceiveDispatch Kind = 20 // original receive preparation and dispatch decisions
	KindWALRead         Kind = 21 // original bounded WAL readable-prefix observations
	KindRestore         Kind = 22 // actual restore planning, attempts and installation
	KindSigner          Kind = 23 // original public signer state and persistence operations
	KindSignerCall      Kind = 24 // original runner signing and own-message WAL call
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
	case KindTimer:
		return "timer"
	case KindCache:
		return "cache"
	case KindSync:
		return "sync"
	case KindWriteCache:
		return "write_cache"
	case KindReceiveCache:
		return "receive_cache"
	case KindSession:
		return "session"
	case KindCoreStep:
		return "core_step_source"
	case KindAppQueue:
		return "app_queue_source"
	case KindInbox:
		return "inbox"
	case KindInternal:
		return "internal_source"
	case KindSelection:
		return "input_selection_source"
	case KindSigner:
		return "signer_source"
	case KindSignerCall:
		return "signer_call_source"
	case KindRestore:
		return "restore_source"
	case KindWALRead:
		return "wal_read_source"
	case KindReceiveDispatch:
		return "receive_dispatch_source"
	case KindFinalize:
		return "finalize_source"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Record is one journal record. Body is one of *SegmentRec, *PeerRec,
// *MsgRec, *OutcomeRec, *SuppressedRec, *StepRec, *GapRec, *TimerRec, *CacheRec,
// *WriteCacheRec, *ReceiveCacheRec, *SessionRec, *CoreStepRec, *AppQueueRec, *FinalizeRec, *InboxRec, *InternalRec, *SelectionRec, *ReceiveDispatchRec, *WALReadRec, *RestoreRec, *SignerRec, *SignerCallRec, or *SyncRec. JSeq is assigned
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
	CachePolicy           *CachePolicyOptions `json:"cache_policy,omitempty"`
	NextHeight            *DeferredOptions    `json:"next_height,omitempty"`
	ProposerPolicyProfile string              `json:"proposer_policy_profile,omitempty"`
	TimerTrace            uint64              `json:"timer_trace,omitempty"`
	CacheTrace            uint64              `json:"cache_trace,omitempty"`
	SyncTrace             uint64              `json:"sync_trace,omitempty"`
	ChainConfig           []byte
	Self                  types.Address
	Improvements          uint64
	BacklogLimit          uint64
	Profile               string
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
	// By and Cause of a closed stream: who closed it and, when the node
	// did, why (transport.Close). Empty when the transport did not say.
	By, Cause string
}

// Directions of MsgRec.
const (
	In  = "in"
	Out = "out"
)

// MsgRec is one consensus message on the wire.
// SendAttempt is a local writer's queue attempt, independent of physical
// frame timing. Zero cache coordinates make no cache-operation claim.
type SendAttempt struct{ Sequence, Cache, Operation uint64 }

type MsgRec struct {
	// Session is the original adapter loop owner; nil makes no stream claim.
	Session      *SessionRef
	WriteAttempt *WriteAttemptSource
	Attempt      *SendAttempt
	// IO is absent in old recordings and when the transport reports no interval.
	IO *IOInterval
	// Capture identifies this received frame within its writer run. It is
	// assigned before Offer and remains stable when recording is asynchronous.
	Capture uint64

	Dir      string
	PeerIdx  uint32
	Mono     time.Duration
	WallNs   int64
	Code     uint64
	WireCode uint64
	Payload  []byte // not copied; the caller must not reuse the slice
	// Size is the length of the payload on the wire; it is kept when the
	// payload is not (a frame too large to keep). 0 means len(Payload).
	Size uint64
	// Engine is the state of the consensus engine when a received frame
	// was recorded: running, stopped or syncing; empty when unknown.
	Engine   string
	DedupKey types.Hash
	// Dedup holds the hits of the two dedup caches when the node checked a
	// received frame against them; nil when it did not (the frame was not
	// queued, or the engine was not running).
	Dedup   *DedupHits
	Offer   string          // In only: queued, queue_full, frame_ignore, frame_disconnect
	Cause   event.SendCause // Out only
	RelayOf uint64          // Out only: jseq of the received message, 0 if none
	Write   string          // Out only: ok, error, not_attached
}

// DedupHits are the hits of a received frame's key in the dedup caches
// (R-01 frame.dedup): the known cache, and the recent cache of the peer it
// came from, before the frame's key was added.
type DedupHits struct {
	Known      bool
	PeerRecent bool
}

// rlpDedup encodes h as 0 (not checked) or 1 | known<<1 | peer_recent<<2.
func rlpDedup(h *DedupHits) uint64 {
	if h == nil {
		return 0
	}
	v := uint64(1)
	if h.Known {
		v |= 2
	}
	if h.PeerRecent {
		v |= 4
	}
	return v
}

func dedupOf(v uint64) *DedupHits {
	if v == 0 {
		return nil
	}
	return &DedupHits{Known: v&2 != 0, PeerRecent: v&4 != 0}
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
	// EngineRun identifies the core incarnation of Step. Zero is unknown
	// for older records and outcomes decided outside a core step.
	EngineRun uint64
	// AtOffer marks an outcome decided while the adapter offered the
	// frame (a known key, the engine not running): it is journaled before
	// the frame and belongs to the next received frame of Peer with
	// DedupKey.
	AtOffer bool
}

// SuppressedRec is a send the recent cache suppressed.
type SuppressedRec struct {
	Cache, Operation uint64
	PeerIdx          uint32
	DedupKey         types.Hash
	Cause            event.SendCause
	Reason           string
}

// StepMoment is a measured step-entry clock pair from the runner.
// Absence means unknown; completion time is never substituted for entry time.
type StepMoment struct {
	Mono   time.Duration
	WallNs int64
}

// StepRec is one input of the core.
type StepRec struct {
	Entry     *StepMoment
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
	Format                uint64
	JSeq                  uint64
	Self                  types.Address
	NodeID                []byte
	BLSPublicKey          []byte
	Run                   string
	Commit                string
	ChainID               *big.Int
	GenesisHash           types.Hash
	Mode                  string
	WireOffset            uint64
	ConfigDigest          types.Hash
	ChainConfig           []byte
	CoreSelf              types.Address
	Improvements          uint64
	BacklogLimit          uint64
	Profile               string
	EngineRun             uint64
	TimerTrace            uint64   `rlp:"optional"`
	CacheTrace            uint64   `rlp:"optional"`
	SyncTrace             uint64   `rlp:"optional"`
	ProposerPolicyProfile string   `rlp:"optional"`
	NextHeight            []uint64 `rlp:"optional"`
	CachePolicy           []uint64 `rlp:"optional"`
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
	By      string
	Cause   string
}

// peerRLPNoClose is a peer record written before records carried By and
// Cause; it still decodes.
type peerRLPNoClose struct {
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
	Format       uint64
	JSeq         uint64
	Dir          string
	PeerIdx      uint64
	Mono         uint64
	WallNs       uint64
	Code         uint64
	WireCode     uint64
	Payload      []byte
	DedupKey     types.Hash
	Offer        string
	Cause        string
	RelayOf      uint64
	Write        string
	Size         uint64
	Engine       string
	Dedup        uint64 // rlpDedup
	Capture      uint64
	IO           []uint64          `rlp:"optional"`
	Attempt      []uint64          `rlp:"optional"`
	Session      []sessionRefRLP   `rlp:"optional"`
	WriteAttempt []writeAttemptRLP `rlp:"optional"`
}

type msgRLPNoCapture struct {
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
	Size     uint64
	Engine   string
	Dedup    uint64 // rlpDedup
}

// msgRLPNoDedup is a msg record written before records carried the dedup
// cache hits; it still decodes.
type msgRLPNoDedup struct {
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
	Size     uint64
	Engine   string
}

// msgRLPNoEngine is a msg record written before records carried the engine
// state; it still decodes.
type msgRLPNoEngine struct {
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
	Size     uint64
}

// msgRLPNoSize is a msg record written before records carried the payload
// size; it still decodes.
type msgRLPNoSize struct {
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
	AtOffer    uint64 // 0 or 1
	EngineRun  uint64 `rlp:"optional"`
}

// outcomeRLPNoAtOffer is an outcome record written before records carried
// AtOffer; it still decodes.
type outcomeRLPNoAtOffer struct {
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
	Format    uint64
	JSeq      uint64
	PeerIdx   uint64
	DedupKey  types.Hash
	Cause     string
	Reason    string
	Cache     uint64 `rlp:"optional"`
	Operation uint64 `rlp:"optional"`
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
	Entry        []uint64 `rlp:"optional"`
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

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
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
			BacklogLimit: b.Core.BacklogLimit, Profile: b.Core.Profile, EngineRun: b.EngineRun, TimerTrace: b.Core.TimerTrace, CacheTrace: b.Core.CacheTrace, SyncTrace: b.Core.SyncTrace, ProposerPolicyProfile: b.Core.ProposerPolicyProfile, NextHeight: b.Core.NextHeight.encode(), CachePolicy: b.Core.CachePolicy.encode()})
	case *PeerRec:
		return rlp.Encode(&peerRLP{Format: Format, JSeq: jseq, PeerIdx: uint64(b.PeerIdx), Addr: b.Addr, NodeID: bytesOrEmpty(b.NodeID),
			Remote: b.Remote, Event: b.Event, Reason: b.Reason, By: b.By, Cause: b.Cause})
	case *MsgRec:
		io, err := encodeIO(b.IO, b.Mono)
		if err != nil {
			return nil, err
		}
		attempt, err := encodeSendAttempt(b.Attempt)
		if err != nil {
			return nil, err
		}
		if b.WriteAttempt != nil && (b.Attempt != nil || b.Dir != Out) {
			return nil, fmt.Errorf("journal: conflicting write reservation domain")
		}
		writeAttempt, err := encodeWriteAttempt(b.WriteAttempt)
		if err != nil {
			return nil, err
		}
		session, err := encodeSessionRef(b.Session)
		if err != nil {
			return nil, err
		}
		return rlp.Encode(&msgRLP{Format: Format, JSeq: jseq, Dir: b.Dir, PeerIdx: uint64(b.PeerIdx), Mono: uint64(int64(b.Mono)),
			WallNs: uint64(b.WallNs), Code: b.Code, WireCode: b.WireCode, Payload: bytesOrEmpty(b.Payload), DedupKey: b.DedupKey,
			Offer: b.Offer, Cause: string(b.Cause), RelayOf: b.RelayOf, Write: b.Write, Size: b.Size, Engine: b.Engine,
			Dedup: rlpDedup(b.Dedup), Capture: b.Capture, IO: io, Attempt: attempt, Session: session, WriteAttempt: writeAttempt})
	case *OutcomeRec:
		return rlp.Encode(&outcomeRLP{Format: Format, JSeq: jseq, Of: b.Of, Code: b.Code, Peer: b.Peer, DedupKey: b.DedupKey,
			Outcome: string(b.Outcome), Check: b.Check, Row: uint64(b.Row + 1), Reason: b.Reason, ErrorClass: b.ErrorClass,
			Via: b.Via, Step: b.Step, AtOffer: boolUint(b.AtOffer), EngineRun: b.EngineRun})
	case *SuppressedRec:
		if (b.Cache == 0) != (b.Operation == 0) {
			return nil, fmt.Errorf("journal: invalid suppressed cache reference")
		}
		return rlp.Encode(&suppressedRLP{Format: Format, JSeq: jseq, PeerIdx: uint64(b.PeerIdx), DedupKey: b.DedupKey,
			Cause: string(b.Cause), Reason: b.Reason, Cache: b.Cache, Operation: b.Operation})
	case *StepRec:
		env := b.Env
		if env == nil {
			env = [][]byte{}
		}
		gens := b.TimerGens
		if gens == nil {
			gens = []uint64{}
		}
		var entry []uint64
		if b.Entry != nil {
			if b.Entry.Mono < 0 || b.Entry.Mono > b.Mono {
				return nil, fmt.Errorf("journal: invalid step entry moment")
			}
			entry = []uint64{uint64(b.Entry.Mono), uint64(b.Entry.WallNs)}
		}
		return rlp.Encode(&stepRLP{Format: Format, JSeq: jseq, EngineRun: b.EngineRun, Step: b.Step, Mono: uint64(int64(b.Mono)),
			WallNs: uint64(b.WallNs), InputKind: b.InputKind, Input: bytesOrEmpty(b.Input), Via: b.Via,
			HeadNumber: heightBig(b.HeadNumber), HeadHash: b.HeadHash, Env: env, ValsetDigest: b.ValsetDigest, OutDigest: b.OutDigest, TimerGens: gens, Entry: entry})
	case *TimerRec:
		return encodeTimerRec(b, jseq)
	case *CacheRec:
		return encodeCacheRec(b, jseq)
	case *WriteCacheRec:
		return encodeWriteCacheRec(b, jseq)
	case *ReceiveCacheRec:
		return encodeReceiveCacheRec(b, jseq)
	case *SessionRec:
		return encodeSessionRec(b, jseq)
	case *CoreStepRec:
		return encodeCoreStepRec(b, jseq)
	case *AppQueueRec:
		return encodeAppQueueRec(b, jseq)
	case *InboxRec:
		return encodeInboxRec(b, jseq)
	case *InternalRec:
		return encodeInternalRec(b, jseq)
	case *SelectionRec:
		return encodeSelectionRec(b, jseq)
	case *SignerRec:
		return encodeSignerRec(b, jseq)
	case *SignerCallRec:
		return encodeSignerCallRec(b, jseq)
	case *RestoreRec:
		return encodeRestoreRec(b, jseq)
	case *WALReadRec:
		return encodeWALReadRec(b, jseq)
	case *ReceiveDispatchRec:
		return encodeReceiveDispatchRec(b, jseq)
	case *FinalizeRec:
		return encodeFinalizeRec(b, jseq)
	case *SyncRec:
		return encodeSyncRec(b, jseq)
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
		deferred, err := decodeDeferredOptions(w.NextHeight)
		if err != nil {
			return fail(err)
		}
		cache, err := decodeCachePolicyOptions(w.CachePolicy)
		if err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &SegmentRec{EngineRun: w.EngineRun, Identity: Identity{
			Self: w.Self, NodeID: w.NodeID, BLSPublicKey: w.BLSPublicKey, Run: w.Run, Commit: w.Commit, ChainID: w.ChainID,
			GenesisHash: w.GenesisHash, Mode: w.Mode, WireOffset: w.WireOffset, ConfigDigest: w.ConfigDigest,
			Core: CoreOptions{ChainConfig: w.ChainConfig, Self: w.CoreSelf, Improvements: w.Improvements, BacklogLimit: w.BacklogLimit, Profile: w.Profile, TimerTrace: w.TimerTrace, CacheTrace: w.CacheTrace, SyncTrace: w.SyncTrace, ProposerPolicyProfile: w.ProposerPolicyProfile, NextHeight: deferred, CachePolicy: cache},
		}}}, nil
	case KindPeer:
		var w peerRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			var old peerRLPNoClose
			if rlp.DecodeStrict(body, &old) != nil {
				return fail(err)
			}
			w = peerRLP{Format: old.Format, JSeq: old.JSeq, PeerIdx: old.PeerIdx, Addr: old.Addr, NodeID: old.NodeID,
				Remote: old.Remote, Event: old.Event, Reason: old.Reason}
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &PeerRec{PeerIdx: uint32(w.PeerIdx), Addr: w.Addr, NodeID: w.NodeID, Remote: w.Remote, Event: w.Event, Reason: w.Reason, By: w.By, Cause: w.Cause}}, nil
	case KindMsg:
		var w msgRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			var noCapture msgRLPNoCapture
			var noDedup msgRLPNoDedup
			var noEngine msgRLPNoEngine
			var noSize msgRLPNoSize
			switch {
			case rlp.DecodeStrict(body, &noCapture) == nil:
				w = msgRLP{Format: noCapture.Format, JSeq: noCapture.JSeq, Dir: noCapture.Dir, PeerIdx: noCapture.PeerIdx, Mono: noCapture.Mono, WallNs: noCapture.WallNs, Code: noCapture.Code, WireCode: noCapture.WireCode, Payload: noCapture.Payload, DedupKey: noCapture.DedupKey, Offer: noCapture.Offer, Cause: noCapture.Cause, RelayOf: noCapture.RelayOf, Write: noCapture.Write, Size: noCapture.Size, Engine: noCapture.Engine, Dedup: noCapture.Dedup}
			case rlp.DecodeStrict(body, &noDedup) == nil:
				w = msgRLP{Format: noDedup.Format, JSeq: noDedup.JSeq, Dir: noDedup.Dir, PeerIdx: noDedup.PeerIdx, Mono: noDedup.Mono,
					WallNs: noDedup.WallNs, Code: noDedup.Code, WireCode: noDedup.WireCode, Payload: noDedup.Payload,
					DedupKey: noDedup.DedupKey, Offer: noDedup.Offer, Cause: noDedup.Cause, RelayOf: noDedup.RelayOf,
					Write: noDedup.Write, Size: noDedup.Size, Engine: noDedup.Engine}
			case rlp.DecodeStrict(body, &noEngine) == nil:
				w = msgRLP{Format: noEngine.Format, JSeq: noEngine.JSeq, Dir: noEngine.Dir, PeerIdx: noEngine.PeerIdx, Mono: noEngine.Mono,
					WallNs: noEngine.WallNs, Code: noEngine.Code, WireCode: noEngine.WireCode, Payload: noEngine.Payload,
					DedupKey: noEngine.DedupKey, Offer: noEngine.Offer, Cause: noEngine.Cause, RelayOf: noEngine.RelayOf,
					Write: noEngine.Write, Size: noEngine.Size}
			case rlp.DecodeStrict(body, &noSize) == nil:
				w = noSize.withSize()
			default:
				return fail(err)
			}
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		io, err := decodeIO(w.IO, time.Duration(int64(w.Mono)))
		if err != nil {
			return fail(err)
		}
		attempt, err := decodeSendAttempt(w.Attempt)
		if err != nil {
			return fail(err)
		}
		if len(w.WriteAttempt) != 0 && (len(w.Attempt) != 0 || w.Dir != Out) {
			return fail(fmt.Errorf("journal: conflicting write reservation domain"))
		}
		writeAttempt, err := decodeWriteAttempt(w.WriteAttempt)
		if err != nil {
			return fail(err)
		}
		session, err := decodeSessionRef(w.Session)
		if err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &MsgRec{Session: session, WriteAttempt: writeAttempt, Attempt: attempt, IO: io, Dir: w.Dir, PeerIdx: uint32(w.PeerIdx), Mono: time.Duration(int64(w.Mono)),
			WallNs: int64(w.WallNs), Code: w.Code, WireCode: w.WireCode, Payload: w.Payload, DedupKey: w.DedupKey, Offer: w.Offer,
			Cause: event.SendCause(w.Cause), RelayOf: w.RelayOf, Write: w.Write, Size: w.Size, Engine: w.Engine,
			Dedup: dedupOf(w.Dedup), Capture: w.Capture}}, nil
	case KindOutcome:
		var w outcomeRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			var old outcomeRLPNoAtOffer
			if rlp.DecodeStrict(body, &old) != nil {
				return fail(err)
			}
			w = outcomeRLP{Format: old.Format, JSeq: old.JSeq, Of: old.Of, Code: old.Code, Peer: old.Peer, DedupKey: old.DedupKey,
				Outcome: old.Outcome, Check: old.Check, Row: old.Row, Reason: old.Reason, ErrorClass: old.ErrorClass, Via: old.Via, Step: old.Step}
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &OutcomeRec{Of: w.Of, Code: w.Code, Peer: w.Peer, DedupKey: w.DedupKey,
			Outcome: event.OutcomeClass(w.Outcome), Check: w.Check, Row: int64(w.Row) - 1, Reason: w.Reason, ErrorClass: w.ErrorClass,
			Via: w.Via, Step: w.Step, AtOffer: w.AtOffer != 0, EngineRun: w.EngineRun}}, nil
	case KindSuppressed:
		var w suppressedRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		if (w.Cache == 0) != (w.Operation == 0) {
			return fail(fmt.Errorf("invalid suppressed cache reference"))
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &SuppressedRec{Cache: w.Cache, Operation: w.Operation, PeerIdx: uint32(w.PeerIdx), DedupKey: w.DedupKey, Cause: event.SendCause(w.Cause), Reason: w.Reason}}, nil
	case KindStep:
		var w stepRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		if err := check(w.Format); err != nil {
			return fail(err)
		}
		var entry *StepMoment
		if len(w.Entry) > 0 {
			if len(w.Entry) != 2 || int64(w.Entry[0]) < 0 || int64(w.Entry[0]) > int64(w.Mono) {
				return fail(fmt.Errorf("journal: invalid step entry moment"))
			}
			entry = &StepMoment{Mono: time.Duration(w.Entry[0]), WallNs: int64(w.Entry[1])}
		}
		hn, err := types.HeightFromBig(bigOrZero(w.HeadNumber))
		if err != nil {
			return fail(err)
		}
		return Record{Kind: k, JSeq: w.JSeq, Body: &StepRec{EngineRun: w.EngineRun, Step: w.Step, Mono: time.Duration(int64(w.Mono)),
			WallNs: int64(w.WallNs), InputKind: w.InputKind, Input: w.Input, Via: w.Via, HeadNumber: hn, HeadHash: w.HeadHash,
			Env: w.Env, ValsetDigest: w.ValsetDigest, OutDigest: w.OutDigest, TimerGens: w.TimerGens, Entry: entry}}, nil
	case KindTimer:
		return decodeTimerRec(body)
	case KindCache:
		return decodeCacheRec(body)
	case KindWriteCache:
		return decodeWriteCacheRec(body)
	case KindReceiveCache:
		return decodeReceiveCacheRec(body)
	case KindSession:
		return decodeSessionRec(body)
	case KindCoreStep:
		return decodeCoreStepRec(body)
	case KindAppQueue:
		return decodeAppQueueRec(body)
	case KindInbox:
		return decodeInboxRec(body)
	case KindInternal:
		return decodeInternalRec(body)
	case KindSelection:
		return decodeSelectionRec(body)
	case KindSigner:
		return decodeSignerRec(body)
	case KindSignerCall:
		return decodeSignerCallRec(body)
	case KindRestore:
		return decodeRestoreRec(body)
	case KindWALRead:
		return decodeWALReadRec(body)
	case KindReceiveDispatch:
		return decodeReceiveDispatchRec(body)
	case KindFinalize:
		return decodeFinalizeRec(body)
	case KindSync:
		return decodeSyncRec(body)
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
	case *TimerRec:
		return KindTimer, true
	case *CacheRec:
		return KindCache, true
	case *WriteCacheRec:
		return KindWriteCache, true
	case *ReceiveCacheRec:
		return KindReceiveCache, true
	case *SessionRec:
		return KindSession, true
	case *CoreStepRec:
		return KindCoreStep, true
	case *AppQueueRec:
		return KindAppQueue, true
	case *InboxRec:
		return KindInbox, true
	case *InternalRec:
		return KindInternal, true
	case *SelectionRec:
		return KindSelection, true
	case *SignerRec:
		return KindSigner, true
	case *SignerCallRec:
		return KindSignerCall, true
	case *RestoreRec:
		return KindRestore, true
	case *WALReadRec:
		return KindWALRead, true
	case *ReceiveDispatchRec:
		return KindReceiveDispatch, true
	case *FinalizeRec:
		return KindFinalize, true
	case *SyncRec:
		return KindSync, true
	}
	return 0, false
}

// size estimates the queue bytes of a record.
func size(r Record) int64 {
	switch b := r.Body.(type) {
	case *MsgRec:
		n := int64(len(b.Payload)) + 128
		if b.IO != nil {
			n += 48
		}
		if b.Attempt != nil {
			n += 48
		}
		if b.WriteAttempt != nil {
			n += 64 + int64(len(b.WriteAttempt.WriterRun))
		}
		if b.Session != nil {
			n += 48 + int64(len(b.Session.Run))
		}
		return n
	case *TimerRec:
		return int64(len(b.Input)) + 256
	case *CacheRec:
		return 320 + int64(len(b.Candidates)+len(b.Targets)+len(b.Suppressed))*20
	case *WriteCacheRec:
		n := int64(512) + int64(len(b.Transition.Pruned))*8 + int64(len(b.Transition.Input.SessionRun)+len(b.Transition.Receipt.SessionRun))
		if s := b.Transition.AcceptedSource; s != (transport.AcceptedInputSource{}) {
			n += 160 + int64(len(s.LedgerRun)+len(s.Origin.WriterRun)+len(s.Core.Via))
		}
		return n
	case *ReceiveCacheRec:
		return 640 + int64(len(b.Transition.Pruned))*8 + int64(len(b.Transition.Origin.WriterRun)+len(b.Transition.CheckedOrigin.WriterRun)+len(b.Transition.Source.Via)+len(b.Transition.Context.Sequence)+len(b.Transition.Context.Round)+len(b.Transition.Context.State)+len(b.Transition.Context.PriorRound)+len(b.Transition.Input.SessionRun)+len(b.Transition.Checked.SessionRun))
	case *CoreStepRec:
		n := int64(1024 + len(b.Head) + len(b.Input) + len(b.Outputs) + len(b.Origin.WriterRun) + len(b.StreamRun) + len(b.ReceiveLedgerRun) + len(b.InputKind) + len(b.Via) + len(b.Unavailable))
		n += int64(len(b.Before.Sequence) + len(b.Before.Round) + len(b.Before.State) + len(b.Before.PriorRound) + len(b.After.Sequence) + len(b.After.Round) + len(b.After.State) + len(b.After.PriorRound))
		for _, e := range b.Environment {
			n += int64(len(e.Bytes) + 8*len(e.ValidatorKeyPresent) + 32)
		}
		return n
	case *SessionRec:
		n := int64(160 + len(b.Event))
		if b.Session != nil {
			n += 48 + int64(len(b.Session.Run))
		}
		return n
	case *AppQueueRec:
		return 256 + int64(len(b.Input)+len(b.InputKind)+len(b.Action)+len(b.Unavailable))
	case *SignerRec:
		s := b.Source
		return int64(768 + len(s.Ref.Namespace) + len(s.BLSPublicKey) + len(s.Before) + len(s.After) + len(s.Request) + len(s.SealData) + len(s.Signature) + len(s.Seal) + len(s.Write) + len(s.Floor) + len(s.Action) + len(s.Result) + len(s.Unavailable))
	case *SignerCallRec:
		return int64(512 + len(b.Source.Namespace) + len(b.WAL.Namespace) + len(b.Request) + len(b.SealData) + len(b.Signature) + len(b.Seal) + len(b.Payload) + len(b.Result) + len(b.Unavailable))
	case *RestoreRec:
		n := int64(512 + 8*len(b.Generations) + len(b.Read.Namespace) + len(b.From) + len(b.Unavailable) + 8*len(b.Inputs))
		for _, o := range b.Own {
			n += 32 + int64(len(o.Payload))
		}
		for _, a := range b.Attempts {
			n += 256 + 8*int64(len(a.Generations))
			for _, o := range a.Own {
				n += 32 + int64(len(o.Payload))
			}
			for _, t := range a.Timers {
				n += 24 + int64(len(t))
			}
		}
		return n
	case *WALReadRec:
		n := int64(512 + len(b.Source.Namespace) + len(b.Source.Error) + len(b.Source.Unavailable))
		for _, f := range b.Source.Frames {
			n += 32 + int64(len(f.Bytes))
		}
		return n
	case *ReceiveDispatchRec:
		return 512 + int64(len(b.Input)+len(b.InputKind)+len(b.Via)+len(b.Action)+len(b.Source.WriterRun)+len(b.StreamRun)+len(b.Origin.WriterRun)+len(b.Unavailable))
	case *SelectionRec:
		return 512 + int64(len(b.Input)+len(b.InputKind)+len(b.Action)+len(b.Lane)+len(b.NextHeight)+len(b.Unavailable)+len(b.Internal.State)+len(b.App.State)+len(b.Timer.State)+len(b.Inbox.State))
	case *InternalRec:
		return 256 + int64(len(b.Input)+len(b.Action)+len(b.Origin)+len(b.InputKind)+len(b.Unavailable))
	case *InboxRec:
		return 768 + int64(len(b.Payload)+len(b.Action)+len(b.Result)+len(b.Origin.WriterRun)+len(b.StreamRun)+len(b.ViewSequence)+len(b.ViewRound)+len(b.SnapshotPhase)+len(b.Unavailable)+20*(len(b.Order)+len(b.Candidates)))
	case *FinalizeRec:
		return 256 + int64(len(b.Arguments)+len(b.Input)+len(b.QueueRun)+len(b.Action)+len(b.Unavailable))
	case *SyncRec:
		return 256
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

// withSize converts an old msg record (no size; the size is that of its
// payload).
func (o msgRLPNoSize) withSize() msgRLP {
	return msgRLP{Format: o.Format, JSeq: o.JSeq, Dir: o.Dir, PeerIdx: o.PeerIdx, Mono: o.Mono, WallNs: o.WallNs, Code: o.Code,
		WireCode: o.WireCode, Payload: o.Payload, DedupKey: o.DedupKey, Offer: o.Offer, Cause: o.Cause, RelayOf: o.RelayOf,
		Write: o.Write}
}

func encodeSendAttempt(a *SendAttempt) ([]uint64, error) {
	if a == nil {
		return nil, nil
	}
	if a.Sequence == 0 || (a.Cache == 0) != (a.Operation == 0) {
		return nil, fmt.Errorf("journal: invalid send attempt")
	}
	return []uint64{1, a.Sequence, a.Cache, a.Operation}, nil
}

func decodeSendAttempt(w []uint64) (*SendAttempt, error) {
	if len(w) == 0 {
		return nil, nil
	}
	if len(w) != 4 || w[0] != 1 || w[1] == 0 || (w[2] == 0) != (w[3] == 0) {
		return nil, fmt.Errorf("journal: invalid send attempt")
	}
	return &SendAttempt{Sequence: w[1], Cache: w[2], Operation: w[3]}, nil
}
