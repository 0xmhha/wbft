package node

import (
	"encoding/hex"
	"sync"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/metrics"
	"github.com/0xmhha/wbft/types"
)

// validatorLabelLimit is the largest validator set whose members get a
// series of their own (observe.md 5.1, the lighthouse aggregatable_metric
// rule); "total" is always recorded.
const validatorLabelLimit = 64

// validatorMetrics derives the per-validator series of observe.md 5.1 from
// the headers of new heads, so that a node whose core does not run (a
// follower, a non-validator) records them too (observe.md 4.3):
//
//   - wbft_validator_seals_total{validator, type}: the sealers of a head's
//     prepared and committed seals, the sealers of its parent in the head's
//     prev seals, and, as extra, a parent sealer that only the head's prev
//     seal holds (a seal that came late);
//   - wbft_validator_missed_proposals_total{validator}: the proposers of the
//     rounds below the head's round.
//
// Each head number is counted once; a head at or below the last counted one
// (a reorganisation, a restart of the core) is not counted again.
type validatorMetrics struct {
	seals, missed *metrics.Counter
	chain         types.ChainReader
	valsAt        func(types.Height, types.Hash) (*validator.Set, error)

	mu   sync.Mutex
	last types.Height
}

func newValidatorMetrics(r *metrics.Registry) *validatorMetrics {
	return &validatorMetrics{
		seals: r.Counter("wbft_validator_seals_total",
			"Seals in stored headers by validator and type (prepared, committed, prev_prepared, prev_committed, extra).", "validator", "type"),
		missed: r.Counter("wbft_validator_missed_proposals_total",
			"Rounds below a head's round, by their proposer.", "validator"),
	}
}

// attach gives the chain the headers and validator sets are read from; the
// node calls it when it starts.
func (m *validatorMetrics) attach(chain types.ChainReader, valsAt func(types.Height, types.Hash) (*validator.Set, error)) {
	m.mu.Lock()
	m.chain, m.valsAt = chain, valsAt
	m.mu.Unlock()
}

// head counts the seals and missed proposals of a new head. It returns
// without counting when the header or a validator set cannot be read.
func (m *validatorMetrics) head(h *types.Header) {
	if h == nil || h.Number.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.chain == nil || m.valsAt == nil {
		return
	}
	if !m.last.IsZero() && h.Number.Cmp(m.last) <= 0 {
		return
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return
	}
	vs, err := m.valsAt(h.Number, h.ParentHash)
	if err != nil {
		return
	}
	m.last = h.Number
	m.count(vs, x.PreparedSeal, "prepared")
	m.count(vs, x.CommittedSeal, "committed")
	parent := m.chain.Header(h.ParentHash, h.Number.RefLow64()-1) //wbft:low64 HH-28
	for r := uint64(0); r < uint64(x.Round); r++ {
		p := vs.CalcProposer(types.ProposerOf(parent), r)
		if p >= 0 {
			m.inc(m.missed, vs, vs.At(p).Addr)
		}
	}
	if parent == nil || parent.Number.IsZero() {
		return
	}
	px, err := codec.DecodeExtra(parent)
	if err != nil {
		return
	}
	pvs, err := m.valsAt(parent.Number, parent.ParentHash)
	if err != nil {
		return
	}
	m.count(pvs, x.PrevPreparedSeal, "prev_prepared")
	m.count(pvs, x.PrevCommittedSeal, "prev_committed")
	// Extra: a parent sealer in a prev seal of the head but in neither seal
	// of the parent itself.
	inParent := map[uint32]bool{}
	for _, s := range []*types.AggregatedSeal{px.PreparedSeal, px.CommittedSeal} {
		if s != nil {
			for _, i := range s.Sealers.Sealers() {
				inParent[i] = true
			}
		}
	}
	extra := map[uint32]bool{}
	for _, s := range []*types.AggregatedSeal{x.PrevPreparedSeal, x.PrevCommittedSeal} {
		if s != nil {
			for _, i := range s.Sealers.Sealers() {
				if !inParent[i] {
					extra[i] = true
				}
			}
		}
	}
	for i := range extra { //wbft:unordered counters commute
		if mb, ok := pvs.Get(uint64(i)); ok {
			m.inc(m.seals, pvs, mb.Addr, "extra")
		}
	}
}

// count adds one seal of type t for every sealer of s.
func (m *validatorMetrics) count(vs *validator.Set, s *types.AggregatedSeal, t string) {
	if s == nil {
		return
	}
	for _, i := range s.Sealers.Sealers() {
		if mb, ok := vs.Get(uint64(i)); ok {
			m.inc(m.seals, vs, mb.Addr, t)
		}
	}
}

// inc adds one to the "total" series and, for a set within the label limit,
// to the validator's own series; extra are the labels after validator.
func (m *validatorMetrics) inc(c *metrics.Counter, vs *validator.Set, a types.Address, extra ...string) {
	c.Inc(append([]string{"total"}, extra...)...)
	if vs.Len() <= validatorLabelLimit {
		c.Inc(append([]string{"0x" + hex.EncodeToString(a[:])}, extra...)...)
	}
}
