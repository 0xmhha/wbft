package node

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
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
//
// wbft_validator_message_delay_seconds{validator, code} comes from the event
// records (observe): the first PRE-PREPARE, PREPARE, COMMIT and
// ROUND-CHANGE of each source in a view, less the start of the round
// (observe.md 4.1): Time(h-1) + BP(h) for round 0, the time of this node's
// ROUND_ENTER otherwise. Messages the receive prefilter dropped are not
// arrivals. A view whose start is unknown (the parent header
// not seen, a message ahead of the node's view) is not recorded. Above the
// label limit the histogram is off.
type validatorMetrics struct {
	seals, missed *metrics.Counter
	delay         *metrics.Histogram
	chain         types.ChainReader
	valsAt        func(types.Height, types.Hash) (*validator.Set, error)
	period        func(types.Height) time.Duration

	mu     sync.Mutex
	last   types.Height
	setLen int               // members of the last head's set
	heads  map[string]uint64 // header times by number, recent ones
	seq    string            // the sequence of the node's current view
	starts map[string]time.Time
	seen   map[delayKey]bool
}

// delayKey is one source's message of one code in one round.
type delayKey struct {
	round, source string
	code          uint64
}

// headsKept is the number of header times kept for round-0 starts.
const headsKept = 8

// delayBuckets are the eight buckets of the delay histogram (observe.md 5.2).
var delayBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}

func newValidatorMetrics(r *metrics.Registry) *validatorMetrics {
	return &validatorMetrics{
		seals: r.Counter("wbft_validator_seals_total",
			"Seals in stored headers by validator and type (prepared, committed, prev_prepared, prev_committed, extra).", "validator", "type"),
		missed: r.Counter("wbft_validator_missed_proposals_total",
			"Rounds below a head's round, by their proposer.", "validator"),
		delay: r.Histogram("wbft_validator_message_delay_seconds",
			"First arrival of a validator's message in a view less the start of the round, by code.", delayBuckets, "validator", "code"),
		heads: map[string]uint64{},
	}
}

// attach gives the chain the headers and validator sets are read from; the
// node calls it when it starts.
func (m *validatorMetrics) attach(chain types.ChainReader, valsAt func(types.Height, types.Hash) (*validator.Set, error),
	period func(types.Height) time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chain, m.valsAt, m.period = chain, valsAt, period
	if h := chain.Head(); h != nil {
		m.keepHead(h)
		if vs, err := valsAt(h.Number.AddUint64(1), codec.BlockHash(h)); err == nil {
			m.setLen = vs.Len()
		}
	}
}

// keepHead keeps the time of h for the round-0 start of its child.
func (m *validatorMetrics) keepHead(h *types.Header) {
	m.heads[h.Number.String()] = h.Time
	for len(m.heads) > headsKept {
		var low *big.Int
		var lowKey string
		for k := range m.heads { //wbft:unordered the minimum
			b, _ := new(big.Int).SetString(k, 10)
			if low == nil || b.Cmp(low) < 0 {
				low, lowKey = b, k
			}
		}
		delete(m.heads, lowKey)
	}
}

// observe takes one event record (event.Writer.Observe).
func (m *validatorMetrics) observe(r event.Record, at event.Stamp) {
	if r.View == nil || (r.Kind != event.RoundEnter && r.Kind != event.MsgOutcome) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Kind == event.RoundEnter {
		if r.View.Seq != m.seq {
			m.seq, m.starts, m.seen = r.View.Seq, map[string]time.Time{}, map[delayKey]bool{}
		}
		if r.View.Round != "0" {
			m.starts[r.View.Round] = at.Wall
			return
		}
		seq, ok := new(big.Int).SetString(r.View.Seq, 10)
		if !ok || seq.Sign() == 0 || m.period == nil {
			return
		}
		pt, ok := m.heads[new(big.Int).Sub(seq, big.NewInt(1)).String()]
		h, err := types.HeightFromBig(seq)
		if !ok || err != nil {
			return
		}
		m.starts["0"] = time.Unix(int64(pt), 0).Add(m.period(h)) //nolint:gosec // header times fit
		return
	}
	src, _ := r.Fields["source"].(string)
	code, ok := codeOf(r.Fields["code"])
	if src == "" || !ok || r.Fields["check"] == "prefilter" || code < uint64(codec.CodePreprepare) || code > uint64(codec.CodeRoundChange) ||
		r.View.Seq != m.seq || m.setLen > validatorLabelLimit {
		return
	}
	start, ok := m.starts[r.View.Round]
	k := delayKey{round: r.View.Round, source: src, code: code}
	if !ok || m.seen[k] {
		return
	}
	m.seen[k] = true
	d := max(at.Wall.Sub(start), 0).Seconds()
	label := fmt.Sprintf("%#x", code)
	m.delay.Observe(d, "total", label)
	m.delay.Observe(d, src, label)
}

// codeOf reads a message code field of any unsigned integer type.
func codeOf(v any) (uint64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint(), true
	}
	return 0, false
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
	m.setLen = vs.Len()
	m.keepHead(h)
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
