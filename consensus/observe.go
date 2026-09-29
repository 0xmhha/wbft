package consensus

import (
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// ValsetDigest is the digest of a validator set in observation records:
// keccak256(rlp([policy, [[address, bls_public_key], ...]])) with the
// members in set order. A nil set has the zero digest.
func ValsetDigest(vs *validator.Set) types.Hash {
	if vs == nil {
		return types.Hash{}
	}
	members := make([]any, vs.Len())
	for i := 0; i < vs.Len(); i++ {
		m := vs.At(i)
		members[i] = []any{m.Addr, m.BLSPublicKey}
	}
	b, err := rlp.Encode([]any{vs.Policy().ID, members})
	if err != nil {
		return types.Hash{}
	}
	return keccak.Sum256(b)
}

// Values of the BACKLOG and EXTRA_SEAL events.
const (
	opPush    = "push"
	opReplay  = "replay"
	opDrop    = "drop"
	opStore   = "store"
	opIgnore  = "ignore"
	opReject  = "reject"
	kindEquiv = "equivocation"
	kindPP0   = "round0_preprepare"
)

func (st *step) backlogEvent(op string, m *Verified, reason string) {
	f := map[string]any{"op": op, "code": uint64(m.Msg.Code), "source": hexAddr(m.Source)}
	if reason != "" {
		f["reason"] = reason
	}
	st.emit(Event{Record: event.Record{Kind: event.Backlog, View: event.ViewOf(m.Msg.View), Fields: f}})
}

func (st *step) extraSealEvent(op string, m *Verified, target *types.Block) {
	f := map[string]any{"op": op, "source": hexAddr(m.Source), "target": nil}
	switch m.Msg.Code {
	case codec.CodePrepare:
		f["seal_type"] = "PREPARE"
	case codec.CodeCommit:
		f["seal_type"] = "COMMIT"
	default:
		f["seal_type"] = nil
	}
	if target != nil {
		f["target"] = hexHash(blockHash(target))
	}
	st.emit(Event{Record: event.Record{Kind: event.ExtraSeal, View: event.ViewOf(m.Msg.View), Fields: f}})
}

// seenKey identifies a signed message of one source in one view.
type seenKey struct {
	seq, round string
	code       codec.Code
	source     types.Address
}

type seenEntry struct {
	seq    types.Height
	digest types.Hash
	sig    []byte
}

// observe records the first digest of each (view, code, source) of the
// previous, the current and the next sequence and emits EVIDENCE when a validly signed
// message with another digest arrives. It changes nothing else: the message
// is handled as the reference handles it. ROUND-CHANGE messages are not
// tracked; the reference replaces them by later ones of the same source.
func (st *step) observe(v *Verified) {
	s := st.s
	m := v.Msg
	var digest types.Hash
	switch m.Code {
	case codec.CodePrepare, codec.CodeCommit:
		digest = m.Digest
	case codec.CodePreprepare:
		if m.Proposal == nil || m.Proposal.Header == nil {
			return
		}
		digest = blockHash(m.Proposal)
	default:
		return
	}
	if s.cur == nil || tooFar(s.cur.view, m.View) {
		return
	}
	if d, ok := s.cur.view.Sequence.Sub(m.View.Sequence); ok && d.CmpUint64(1) > 0 {
		return // only the previous, the current and the next sequence
	}
	k := seenKey{seq: m.View.Sequence.String(), round: m.View.Round.String(), code: m.Code, source: v.Source}
	old, ok := s.seen[k]
	if !ok {
		s.seen[k] = seenEntry{seq: m.View.Sequence, digest: digest, sig: append([]byte(nil), m.Signature...)}
		return
	}
	if old.digest == digest {
		return
	}
	kind := kindEquiv
	if m.Code == codec.CodePreprepare && m.View.Round.IsZero() {
		kind = kindPP0
	}
	st.emit(Event{Record: event.Record{
		Kind: event.Evidence,
		View: event.ViewOf(m.View),
		Fields: map[string]any{
			"code":     uint64(m.Code),
			"source":   hexAddr(v.Source),
			"digest_a": hexHash(old.digest),
			"digest_b": hexHash(digest),
			"sig_a":    hexBytes(old.sig),
			"sig_b":    hexBytes(m.Signature),
			"kind":     kind,
		},
	}})
}

// pruneSeen drops the entries below the previous sequence of seq.
func (s *State) pruneSeen(seq types.Height) {
	for k, e := range s.seen { //wbft:unordered deletion only
		if d, ok := seq.Sub(e.seq); ok && d.CmpUint64(1) > 0 {
			delete(s.seen, k)
		}
	}
}
