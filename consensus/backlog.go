// Copyright 2017 The go-ethereum Authors
// Copyright 2024 The go-wemix-wbft Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// addToBacklog, processBacklog and the priority follow
// consensus/wbft/core/backlog.go and the extra-seal handling follows
// consensus/wbft/core/extraseal.go of go-stablenet (commit 740526d03); the
// backlog is derived from quorum/consensus/istanbul/qbft/core/backlog.go.

package consensus

import (
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// backlogKey is the slot of a backlogged message: code and the low 64 bits of
// its sequence and round.
type backlogKey struct {
	code     codec.Code
	sequence uint64
	round    uint64
}

type backlogEntry struct {
	m    *Verified
	key  backlogKey
	prio int64
	seq  uint64
}

// backlogQueue is the queue of one source: highest priority first, ties in
// insertion order.
type backlogQueue struct {
	entries []backlogEntry
	keys    map[backlogKey]bool
	nextSeq uint64
}

func keyOf(m *codec.Message) backlogKey {
	return backlogKey{
		code:     m.Code,
		sequence: m.View.Sequence.RefLow64(), //wbft:low64 HH-12
		round:    m.View.Round.RefLow64(),    //wbft:low64 HH-12
	}
}

// backlogPriority is the release priority: ROUND-CHANGE first, then by round,
// and within a round PRE-PREPARE, COMMIT, PREPARE; computed in 64-bit
// arithmetic on the low bits of sequence and round.
//
// Spec: WBFT-SM-072
func backlogPriority(m *codec.Message) int64 {
	seq := m.View.Sequence.RefLow64() //wbft:low64 HH-12
	if m.Code == codec.CodeRoundChange {
		return -int64(seq * 1000)
	}
	var p uint64
	switch m.Code {
	case codec.CodePreprepare:
		p = 1
	case codec.CodeCommit:
		p = 2
	case codec.CodePrepare:
		p = 3
	}
	round := m.View.Round.RefLow64() //wbft:low64 HH-12
	return -int64(seq*1000 + round*10 + p)
}

func (q *backlogQueue) push(e backlogEntry) {
	i := 0
	for i < len(q.entries) && !before(e.prio, e.seq, q.entries[i].prio, q.entries[i].seq) {
		i++
	}
	q.entries = append(q.entries, backlogEntry{})
	copy(q.entries[i+1:], q.entries[i:])
	q.entries[i] = e
}

// addToBacklog is add_to_backlog: messages of the node itself, a slot that is
// already queued for the source and a full queue are discarded.
//
// Spec: WBFT-SM-069, WBFT-SM-070, WBFT-SM-071
func (st *step) addToBacklog(v *Verified) int {
	s := st.s
	if v.Source == s.opt.Self {
		return rowBacklogDropped
	}
	k := keyOf(v.Msg)
	q := s.backlog[v.Source]
	if q == nil {
		q = &backlogQueue{keys: make(map[backlogKey]bool)}
		s.backlog[v.Source] = q
	} else {
		if q.keys[k] {
			return rowBacklogDropped
		}
		if len(q.entries) >= s.opt.BacklogLimit {
			return rowBacklogDropped
		}
	}
	q.keys[k] = true
	q.nextSeq++
	q.push(backlogEntry{m: v, key: k, prio: backlogPriority(v.Msg), seq: q.nextSeq})
	return rowBacklogged
}

// processBacklog is process_backlog: the queues of sources outside the
// current set are dropped; each other queue is released in priority order
// until its first message that is still FUTURE, which is put back. Messages
// classified PROCESS or EXTRA_SEAL are scheduled for replay; the others are
// dropped. Sources are visited in address order.
//
// Spec: WBFT-SM-073
func (st *step) processBacklog() {
	s := st.s
	for _, src := range sortedAddrs(s.backlog) {
		q := s.backlog[src]
		if !s.validators.Contains(src) {
			delete(s.backlog, src)
			continue
		}
		for len(q.entries) > 0 {
			e := q.entries[0]
			cls := CheckMessage(s.cur.view, s.state, s.prior.round, e.m.Msg.Code, e.m.Msg.View)
			if cls == Future {
				break
			}
			q.entries = q.entries[1:]
			delete(q.keys, e.key)
			if cls == Process || cls == ExtraSeal {
				st.emit(Schedule{In: Replay{Msg: e.m}})
			}
		}
	}
}

// addExtraSeal is add_extra_seal: the target is the prior proposal in
// AcceptRequest and the current proposal otherwise. Without a target nothing
// is stored and the result is OK.
//
// Spec: WBFT-SM-063, WBFT-SM-064
func (st *step) addExtraSeal(v *Verified) (bool, int) {
	s := st.s
	var block *types.Block
	vs := s.validators
	if s.state == AcceptRequest {
		block, vs = s.prior.proposal, s.prior.validators
	} else if s.cur.preprepare != nil {
		block = s.cur.preprepare.Msg.Proposal
	}
	if block == nil {
		return true, rowExtraNoTarget
	}
	var into map[types.Address]*Verified
	switch v.Msg.Code {
	case codec.CodePrepare:
		into = s.extraPrepare
	case codec.CodeCommit:
		into = s.extraCommit
	default:
		return false, rowExtraOtherCode
	}
	if !checkVote(vs, block, v) {
		return false, rowExtraInvalid
	}
	if storeExtra(into, v) {
		return true, rowExtraStored
	}
	return true, rowExtraNotNewer
}

// storeExtra is store_extra: one message per source, replaced only by a
// message of a greater view. It reports whether v was stored.
//
// Spec: WBFT-SM-065
func storeExtra(into map[types.Address]*Verified, v *Verified) bool {
	if old := into[v.Source]; old != nil && old.Msg.View.Cmp(v.Msg.View) >= 0 {
		return false
	}
	into[v.Source] = v
	return true
}

// addEffectiveSealsToExtraSeals stores the PREPAREs and COMMITs of the round
// being left as extra seals.
//
// Spec: WBFT-SM-066
func (st *step) addEffectiveSealsToExtraSeals() {
	s := st.s
	for _, a := range sortedAddrs(s.cur.prepares) {
		storeExtra(s.extraPrepare, s.cur.prepares[a])
	}
	for _, a := range sortedAddrs(s.cur.commits) {
		storeExtra(s.extraCommit, s.cur.commits[a])
	}
}

// clearExtraSeals deletes the extra seals whose sequence is below n.
//
// Spec: WBFT-SM-068
func (st *step) clearExtraSeals(n types.Height) {
	s := st.s
	for _, m := range []map[types.Address]*Verified{s.extraPrepare, s.extraCommit} {
		for _, a := range sortedAddrs(m) {
			if m[a].Msg.View.Sequence.Cmp(n) < 0 {
				delete(m, a)
			}
		}
	}
}
