package runner

import (
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// walFormat is the format number of the runner's WAL records.
const walFormat = 1

// Kinds of WAL records.
const (
	walRunStart  uint8 = 1 // a run of the engine started at height From
	walInput     uint8 = 2 // one core input, before the core handles it
	walEnv       uint8 = 3 // one Env call and its answer
	walOwnMsg    uint8 = 4 // an own message, signed, before it is sent; or a refusal
	walCommit    uint8 = 5 // a decided block handed to the application
	walEndHeight uint8 = 6 // the core left for height From after a new head
)

type inputRec struct {
	Kind string
	Body []byte
}

func encodeInput(kind string, body []byte) wal.Record {
	b, _ := rlp.Encode(&inputRec{Kind: kind, Body: body})
	return wal.Record{Format: walFormat, Kind: walInput, Body: b}
}

func encodeEnv(b []byte) wal.Record {
	return wal.Record{Format: walFormat, Kind: walEnv, Body: b}
}

// ownRec is an own message: the signed payload, or a refusal of privval
// for the view (Seq, Round).
type ownRec struct {
	Code    uint64
	Payload []byte
	Refused uint64
	Seq     *big.Int
	Round   *big.Int
}

func encodeOwn(o ownRec) wal.Record {
	if o.Payload == nil {
		o.Payload = []byte{}
	}
	if o.Seq == nil {
		o.Seq = new(big.Int)
	}
	if o.Round == nil {
		o.Round = new(big.Int)
	}
	b, _ := rlp.Encode(&o)
	return wal.Record{Format: walFormat, Kind: walOwnMsg, Body: b}
}

type commitRec struct {
	Block []byte
	Round *big.Int
}

func encodeCommit(b *types.Block, round types.Round) (wal.Record, error) {
	bb, err := codec.EncodeBlock(b)
	if err != nil {
		return wal.Record{}, err
	}
	body, err := rlp.Encode(&commitRec{Block: bb, Round: round.Big()})
	return wal.Record{Format: walFormat, Kind: walCommit, Body: body}, err
}

// boundaryRec starts the records of height From: a run start or the end
// of the height below. It carries what a replay needs to start a core at
// From: the head and the validator set of From.
type boundaryRec struct {
	From       types.Height
	Head       *types.Header
	Validators *validator.Set
	// Replayed is false for a run start whose core did not continue from a
	// replay: the records before it do not describe its state.
	Replayed bool
	// Gens are the timer generations of the core before the step that
	// entered height From (zero for a new core).
	Gens [3]uint64
}

type boundaryRLP struct {
	From     *big.Int
	Head     []byte
	HasSet   uint64
	Policy   uint64
	Addrs    []types.Address
	Keys     [][]byte
	Replayed uint64
	Gens     []uint64
}

func encodeBoundary(kind uint8, b boundaryRec) (wal.Record, error) {
	h, err := codec.EncodeHeader(b.Head)
	if err != nil {
		return wal.Record{}, err
	}
	w := boundaryRLP{From: b.From.Big(), Head: h, Addrs: []types.Address{}, Keys: [][]byte{}, Gens: b.Gens[:]}
	if b.Validators != nil {
		w.HasSet, w.Policy = 1, b.Validators.Policy().ID
		for i := 0; i < b.Validators.Len(); i++ {
			m := b.Validators.At(i)
			w.Addrs = append(w.Addrs, m.Addr)
			w.Keys = append(w.Keys, m.BLSPublicKey)
		}
	}
	if b.Replayed {
		w.Replayed = 1
	}
	body, err := rlp.Encode(&w)
	return wal.Record{Format: walFormat, Kind: kind, Body: body}, err
}

func decodeBoundary(body []byte) (boundaryRec, error) {
	var w boundaryRLP
	if err := rlp.DecodeStrict(body, &w); err != nil {
		return boundaryRec{}, err
	}
	from, err := types.HeightFromBig(w.From)
	if err != nil {
		return boundaryRec{}, err
	}
	h, err := codec.DecodeHeader(w.Head)
	if err != nil {
		return boundaryRec{}, err
	}
	b := boundaryRec{From: from, Head: h, Replayed: w.Replayed == 1}
	if len(w.Gens) != 3 {
		return boundaryRec{}, fmt.Errorf("runner: boundary record with %d timer generations", len(w.Gens))
	}
	copy(b.Gens[:], w.Gens)
	if w.HasSet == 1 {
		if b.Validators, err = validator.NewSet(w.Addrs, w.Keys, types.ProposerPolicy{ID: w.Policy}); err != nil {
			return boundaryRec{}, err
		}
	}
	return b, nil
}

// walStep is one recorded input with the records that followed it.
type walStep struct {
	kind  string
	body  []byte
	env   [][]byte
	own   []ownRec
	index int // position of the input record
}

// CommitRequest is a decided block the write-ahead log handed to the
// application.
type CommitRequest struct {
	Block *types.Block
	Round types.Round
}

// WALState is what the start-up handshake reads from the write-ahead log.
type WALState struct {
	// LastEnd is the height of the last end-of-height record: the highest
	// height the core left after a new head; nil when there is none.
	LastEnd *types.Height
	// Commits are the commit requests in the log, in order, including those
	// of heights the core has already left.
	Commits []CommitRequest
}

// InspectWAL reads the write-ahead log in dir for the start-up handshake.
func InspectWAL(fs fsys.FS, dir string) (WALState, error) {
	var st WALState
	recs, _, err := wal.ReadAll(fs, dir)
	if err != nil {
		return st, err
	}
	for _, rec := range recs {
		if rec.Format != walFormat {
			continue
		}
		switch rec.Kind {
		case walEndHeight:
			b, err := decodeBoundary(rec.Body)
			if err != nil {
				return st, err
			}
			h, _ := b.From.Sub(types.HeightFromUint64(1))
			st.LastEnd = &h
		case walCommit:
			var c commitRec
			if err := rlp.DecodeStrict(rec.Body, &c); err != nil {
				return st, err
			}
			blk, err := codec.DecodeBlock(c.Block)
			if err != nil {
				return st, err
			}
			r, err := types.RoundFromBig(c.Round)
			if err != nil {
				return st, err
			}
			st.Commits = append(st.Commits, CommitRequest{Block: blk, Round: r})
		}
	}
	return st, nil
}

// HandshakeAction is what the node does before it starts the engine.
type HandshakeAction uint8

// Handshake actions.
const (
	// StartNormal: start at the application head + 1.
	StartNormal HandshakeAction = iota
	// Refinalize: the log handed a decided block of height head + 1 to the
	// application, which did not store it; finalize it again and start at
	// head + 2.
	Refinalize
	// StartAfterRollback: the log is one height ahead without a commit
	// request (the application rolled back); start at head + 1 and warn.
	StartAfterRollback
	// Refuse: the log or the sign state is more than one height ahead of
	// the application.
	Refuse
)

// ErrAppBehind is the refusal of the handshake.
var ErrAppBehind = fmt.Errorf("runner: the application is behind the write-ahead log or the sign state")

// Handshake compares the application head appHead with the log state and
// the sign height (the highest signed height or the sign floor, nil if
// none) and returns the action and, for Refinalize, the block.
//
// A commit request of height appHead + 1 is refinalized only when the log
// has not left a later height and nothing was signed beyond appHead + 2:
// the log keeps the requests of earlier heights, and an application that
// fell further behind than one height is refused even when the log still
// holds the request of its next height.
func Handshake(appHead types.Height, st WALState, signHeight *types.Height) (HandshakeAction, *CommitRequest, error) {
	next := appHead.AddUint64(1)
	after := next.AddUint64(1)
	for i := len(st.Commits) - 1; i >= 0; i-- {
		c := st.Commits[i]
		if c.Block.Header.Number.Cmp(next) != 0 {
			continue
		}
		if (st.LastEnd == nil || st.LastEnd.Cmp(next) <= 0) && (signHeight == nil || signHeight.Cmp(after) <= 0) {
			return Refinalize, &c, nil
		}
		break
	}
	if st.LastEnd != nil && st.LastEnd.Cmp(next) > 0 || signHeight != nil && signHeight.Cmp(next) > 0 {
		return Refuse, nil, ErrAppBehind
	}
	if st.LastEnd != nil && st.LastEnd.Cmp(next) == 0 {
		return StartAfterRollback, nil, nil
	}
	return StartNormal, nil, nil
}
