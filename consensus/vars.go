package consensus

import (
	"bytes"
	"slices"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// Vars are the state variables of A-05 section 3.1 after a Step, with every
// set sorted: sources by address, round-change entries by round, backlog
// entries by source, code, sequence and round. Blocks are given by block
// hash. Vars is the "state" record of the steps vectors.
type Vars struct {
	View              types.View
	State             StateName
	Proposer          types.Address
	LockedRound       *types.Round
	LockedBlock       *types.Hash
	Preprepare        *PreprepareVar
	PendingRequest    *types.Hash
	PreprepareSent    types.Round
	Prepares          []types.Address
	Commits           []types.Address
	Certificate       []VoteVar // nil when there is no prepared certificate
	RoundChanges      []RoundChangeVar
	Backlog           []BacklogVar
	PriorRound        types.Round
	PriorProposal     *types.Hash
	ExtraPrepareSeals []VoteVar
	ExtraCommitSeals  []VoteVar
}

// PreprepareVar is the last accepted PRE-PREPARE.
type PreprepareVar struct {
	Round    types.Round
	Proposal types.Hash
}

// VoteVar is a stored PREPARE or COMMIT.
type VoteVar struct {
	Source types.Address
	View   types.View
	Digest types.Hash
}

// RoundChangeVar is one round of the round-change set.
type RoundChangeVar struct {
	Round         uint64
	Sources       []types.Address
	PreparedRound *types.Round
	PreparedBlock *types.Hash
}

// BacklogVar is one backlogged message.
type BacklogVar struct {
	Source types.Address
	Code   codec.Code
	View   types.View
}

// Vars returns the state variables, or nil while the core is stopped or
// before it entered a view.
func (s *State) Vars() *Vars {
	if !s.running || s.cur == nil {
		return nil
	}
	c := s.cur
	v := &Vars{
		View:           c.view,
		State:          s.state,
		Proposer:       s.proposerAddress(),
		LockedRound:    c.preparedRound,
		PreprepareSent: c.preprepareSent,
		Prepares:       sortedAddrs(c.prepares),
		Commits:        sortedAddrs(c.commits),
		PriorRound:     s.prior.round,
	}
	if c.preparedBlock != nil {
		h := blockHash(c.preparedBlock)
		v.LockedBlock = &h
	}
	if c.preprepare != nil {
		v.Preprepare = &PreprepareVar{Round: c.preprepare.Msg.View.Round, Proposal: blockHash(c.preprepare.Msg.Proposal)}
	}
	if c.pendingRequest != nil {
		h := blockHash(c.pendingRequest)
		v.PendingRequest = &h
	}
	if s.certificate != nil {
		v.Certificate = voteVars(s.certificate)
	}
	for _, k := range s.rcs.sortedKeys() {
		e := s.rcs.rounds[k]
		rv := RoundChangeVar{Round: k, Sources: sortedAddrs(e.msgs), PreparedRound: e.highestRound}
		if e.highestBlock != nil {
			h := blockHash(e.highestBlock)
			rv.PreparedBlock = &h
		}
		v.RoundChanges = append(v.RoundChanges, rv)
	}
	for _, src := range sortedAddrs(s.backlog) {
		for _, e := range s.backlog[src].entries {
			v.Backlog = append(v.Backlog, BacklogVar{Source: src, Code: e.m.Msg.Code, View: e.m.Msg.View})
		}
	}
	slices.SortStableFunc(v.Backlog, func(a, b BacklogVar) int {
		if c := bytes.Compare(a.Source[:], b.Source[:]); c != 0 {
			return c
		}
		if a.Code != b.Code {
			if a.Code < b.Code {
				return -1
			}
			return 1
		}
		return a.View.Cmp(b.View)
	})
	if s.prior.proposal != nil {
		h := blockHash(s.prior.proposal)
		v.PriorProposal = &h
	}
	v.ExtraPrepareSeals = voteVars(mapValues(s.extraPrepare))
	v.ExtraCommitSeals = voteVars(mapValues(s.extraCommit))
	return v
}

func mapValues(m map[types.Address]*Verified) []*Verified {
	out := make([]*Verified, 0, len(m))
	for _, a := range sortedAddrs(m) {
		out = append(out, m[a])
	}
	return out
}

func voteVars(vs []*Verified) []VoteVar {
	out := make([]VoteVar, len(vs))
	for i, x := range vs {
		out[i] = VoteVar{Source: x.Source, View: x.Msg.View, Digest: x.Msg.Digest}
	}
	slices.SortStableFunc(out, func(a, b VoteVar) int { return bytes.Compare(a.Source[:], b.Source[:]) })
	return out
}

// Snapshot is an immutable summary of the core for publication to other
// goroutines: the view, the proposer and what the block builder needs to
// select extra seals.
type Snapshot struct {
	Running         bool
	View            types.View
	State           StateName
	Proposer        types.Address
	IsProposer      bool
	Validators      *validator.Set
	PriorRound      types.Round
	PriorValidators *validator.Set
	ExtraPrepare    []ExtraSealEntry
	ExtraCommit     []ExtraSealEntry
}

// ExtraSealEntry is one stored extra seal.
type ExtraSealEntry struct {
	Source types.Address
	View   types.View
	Digest types.Hash
	Seal   []byte
}

// Snapshot returns the current summary. The result shares no mutable state
// with the core.
func (s *State) Snapshot() *Snapshot {
	snap := &Snapshot{Running: s.running && s.cur != nil}
	if !snap.Running {
		return snap
	}
	snap.View = s.cur.view
	snap.State = s.state
	snap.Proposer = s.proposerAddress()
	snap.IsProposer = s.isProposer(s.opt.Self)
	snap.Validators = s.validators
	snap.PriorRound = s.prior.round
	snap.PriorValidators = s.prior.validators
	conv := func(m map[types.Address]*Verified) []ExtraSealEntry {
		out := make([]ExtraSealEntry, 0, len(m))
		for _, a := range sortedAddrs(m) {
			x := m[a]
			out = append(out, ExtraSealEntry{Source: a, View: x.Msg.View, Digest: x.Msg.Digest, Seal: append([]byte(nil), x.Msg.Seal...)})
		}
		return out
	}
	snap.ExtraPrepare = conv(s.extraPrepare)
	snap.ExtraCommit = conv(s.extraCommit)
	return snap
}

// ExtraSeals is process_extra_seals for the head at build time: the stored
// seals for (head number, prior round) with the head's block hash, indexed in
// the prior validator set. Both lists are empty when the core is not running.
//
// Spec: WBFT-SM-067, WBFT-HDR-035
func (snap *Snapshot) ExtraSeals(head *types.Header) (prepared, committed []types.SealEntry) {
	prepared, committed = []types.SealEntry{}, []types.SealEntry{}
	if snap == nil || !snap.Running || head == nil || snap.PriorValidators == nil {
		return prepared, committed
	}
	target := types.View{Sequence: head.Number, Round: snap.PriorRound}
	hash := codec.BlockHash(head)
	pick := func(in []ExtraSealEntry) []types.SealEntry {
		out := []types.SealEntry{}
		for _, e := range in {
			if e.View.Cmp(target) != 0 || e.Digest != hash {
				continue
			}
			if i, ok := snap.PriorValidators.IndexOf(e.Source); ok {
				out = append(out, types.SealEntry{Sealer: uint32(i), Seal: append([]byte(nil), e.Seal...)})
			}
		}
		return out
	}
	return pick(snap.ExtraPrepare), pick(snap.ExtraCommit)
}
