package stepdriver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// obj is a JSON object of a record.
type obj = map[string]any

func hexOut(b []byte) string { return "0x" + hex.EncodeToString(b) }

func addrOut(a types.Address) string { return hexOut(a[:]) }

func hashOut(h types.Hash) string { return hexOut(h[:]) }

func addrList(as []types.Address) []any {
	out := make([]any, len(as))
	for i, a := range as {
		out[i] = addrOut(a)
	}
	return out
}

func viewOut(v types.View) obj {
	return obj{"sequence": v.Sequence.String(), "round": v.Round.String()}
}

func roundPtr(r *types.Round) any {
	if r == nil {
		return nil
	}
	return r.String()
}

func hashPtr(h *types.Hash) any {
	if h == nil {
		return nil
	}
	return hashOut(*h)
}

// record is the record of one step (A-11 section 3.1 "Steps").
type record struct {
	check     any
	relay     any
	sent      []obj
	timers    []obj
	newRound  []any
	finalized any
	scheduled []scheduledRec
	state     any

	// network runner
	outcome  any
	dedupKey any
	relayTo  any
}

type scheduledRec struct {
	source  types.Address
	request bool
	value   obj
}

func newRecord() *record {
	return &record{sent: []obj{}, timers: []obj{}, newRound: []any{}}
}

// out renders the record. A network record has the three network fields in
// front; while the engine is stopped it has only those.
func (r *record) out(network, stopped bool) obj {
	o := obj{}
	if network {
		o["outcome"] = r.outcome
		o["dedup_key"] = r.dedupKey
		o["relay_to"] = r.relayTo
		if stopped {
			return o
		}
	}
	// Backlog replays sorted by source (release order kept for one source),
	// then requests.
	sched := slices.Clone(r.scheduled)
	slices.SortStableFunc(sched, func(a, b scheduledRec) int {
		if a.request != b.request {
			if a.request {
				return 1
			}
			return -1
		}
		if a.request {
			return 0
		}
		return bytes.Compare(a.source[:], b.source[:])
	})
	scheduled := make([]any, len(sched))
	for i, s := range sched {
		scheduled[i] = s.value
	}
	sent := make([]any, len(r.sent))
	for i, s := range r.sent {
		sent[i] = s
	}
	timers := make([]any, len(r.timers))
	for i, t := range r.timers {
		timers[i] = t
	}
	o["check"] = r.check
	o["relay"] = r.relay
	o["sent"] = sent
	o["timers"] = timers
	o["new_round"] = r.newRound
	o["finalized"] = r.finalized
	o["scheduled"] = scheduled
	o["state"] = r.state
	return o
}

var codeNames = map[codec.Code]string{
	codec.CodePreprepare:  "PREPREPARE",
	codec.CodePrepare:     "PREPARE",
	codec.CodeCommit:      "COMMIT",
	codec.CodeRoundChange: "ROUND_CHANGE",
}

// encodedList returns the encodings of ms sorted by their bytes.
func encodedList(ms []*codec.Message, enc func(*codec.Message) ([]byte, error)) ([]any, error) {
	bs := make([][]byte, len(ms))
	for i, m := range ms {
		b, err := enc(m)
		if err != nil {
			return nil, err
		}
		bs[i] = b
	}
	slices.SortStableFunc(bs, bytes.Compare)
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = hexOut(b)
	}
	return out, nil
}

// messageOut renders a message with the fields of encoding/message_codec.
// Justification lists are sorted by the bytes of their members; encoded is
// null when a list has two or more members.
func messageOut(m *codec.Message) (obj, error) {
	o := obj{
		"code":      decU(uint64(m.Code)),
		"type":      codeNames[m.Code],
		"sequence":  m.View.Sequence.String(),
		"round":     m.View.Round.String(),
		"signature": hexOut(m.Signature),
	}
	multi := false
	switch m.Code {
	case codec.CodePrepare, codec.CodeCommit:
		o["digest"] = hashOut(m.Digest)
		o["seal"] = hexOut(m.Seal)
	case codec.CodeRoundChange:
		o["prepared_round"] = roundPtr(m.PreparedRound)
		o["prepared_digest"] = hashOut(m.PreparedDigest)
		o["prepared_block"] = nil
		if m.PreparedBlock != nil {
			b, err := codec.EncodeBlock(m.PreparedBlock)
			if err != nil {
				return nil, err
			}
			o["prepared_block"] = hexOut(b)
		}
		j, err := encodedList(m.Prepares, codec.EncodeMessage)
		if err != nil {
			return nil, err
		}
		o["justification"] = j
		multi = len(j) > 1
	case codec.CodePreprepare:
		prop := []byte{0xc0}
		if m.Proposal != nil {
			var err error
			if prop, err = codec.EncodeBlock(m.Proposal); err != nil {
				return nil, err
			}
		}
		o["proposal"] = hexOut(prop)
		rcs, err := encodedList(m.RoundChanges, codec.EncodeSignedRoundChange)
		if err != nil {
			return nil, err
		}
		ps, err := encodedList(m.Prepares, codec.EncodeMessage)
		if err != nil {
			return nil, err
		}
		o["justification_round_changes"] = rcs
		o["justification_prepares"] = ps
		multi = len(rcs) > 1 || len(ps) > 1
	}
	o["encoded"] = nil
	if !multi {
		enc, err := codec.EncodeMessage(m)
		if err != nil {
			return nil, err
		}
		o["encoded"] = hexOut(enc)
	}
	return o, nil
}

func decU(v uint64) string { return strconv.FormatUint(v, 10) }

// varsOut renders the state variables.
func varsOut(v *consensus.Vars) any {
	if v == nil {
		return nil
	}
	votes := func(vs []consensus.VoteVar, digest bool) []any {
		out := make([]any, len(vs))
		for i, x := range vs {
			o := obj{"source": addrOut(x.Source), "sequence": x.View.Sequence.String(), "round": x.View.Round.String()}
			if digest {
				o["digest"] = hashOut(x.Digest)
			}
			out[i] = o
		}
		return out
	}
	var cert any
	if v.Certificate != nil {
		cert = votes(v.Certificate, true)
	}
	var pp any
	if v.Preprepare != nil {
		pp = obj{"round": v.Preprepare.Round.String(), "proposal": hashOut(v.Preprepare.Proposal)}
	}
	rcs := make([]any, len(v.RoundChanges))
	for i, rc := range v.RoundChanges {
		rcs[i] = obj{
			"round":          decU(rc.Round),
			"sources":        addrList(rc.Sources),
			"prepared_round": roundPtr(rc.PreparedRound),
			"prepared_block": hashPtr(rc.PreparedBlock),
		}
	}
	backlog := make([]any, len(v.Backlog))
	for i, b := range v.Backlog {
		backlog[i] = obj{"source": addrOut(b.Source), "code": decU(uint64(b.Code)), "sequence": b.View.Sequence.String(), "round": b.View.Round.String()}
	}
	return obj{
		"view":                viewOut(v.View),
		"state":               v.State.String(),
		"proposer":            addrOut(v.Proposer),
		"locked_round":        roundPtr(v.LockedRound),
		"locked_block":        hashPtr(v.LockedBlock),
		"preprepare":          pp,
		"pending_request":     hashPtr(v.PendingRequest),
		"preprepare_sent":     v.PreprepareSent.String(),
		"prepares":            addrList(v.Prepares),
		"commits":             addrList(v.Commits),
		"certificate":         cert,
		"round_changes":       rcs,
		"backlog":             backlog,
		"prior":               obj{"round": v.PriorRound.String(), "proposal": hashPtr(v.PriorProposal)},
		"extra_prepare_seals": votes(v.ExtraPrepareSeals, false),
		"extra_commit_seals":  votes(v.ExtraCommitSeals, false),
	}
}

// sealsOut renders a seal list sorted by sealer.
func sealsOut(ss []types.SealEntry) []any {
	c := slices.Clone(ss)
	slices.SortStableFunc(c, func(a, b types.SealEntry) int {
		switch {
		case a.Sealer < b.Sealer:
			return -1
		case a.Sealer > b.Sealer:
			return 1
		}
		return 0
	})
	out := make([]any, len(c))
	for i, s := range c {
		out[i] = obj{"sealer": decU(uint64(s.Sealer)), "seal": hexOut(s.Seal)}
	}
	return out
}

// VarsJSON renders state variables as the "state" record of the steps
// format, as JSON with sorted keys.
func VarsJSON(v *consensus.Vars) string {
	b, err := json.Marshal(varsOut(v))
	if err != nil {
		return err.Error()
	}
	return string(b)
}
