package participation

import (
	"encoding/hex"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// Record is the participation record of one height (participation.md 2).
// Heights and rounds are decimal strings of the full value, addresses and
// hashes 0x-hex. A height the store does not hold comes back with Gap set
// and nothing else: the node did not observe it, or lost it in a crash.
type Record struct {
	Height string `json:"height"`
	Gap    bool   `json:"gap,omitempty"`
	// Source is "local" when this node's core saw the height (its rounds or
	// a message of it), "header" when the record comes from the headers
	// alone (a node whose core does not run, observe.md 4.3).
	Source   string `json:"source,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Round    string `json:"round,omitempty"`    // the committed round
	Proposer string `json:"proposer,omitempty"` // the header's coinbase
	Time     uint64 `json:"time,omitempty"`
	// Rounds lists the rounds 0 to the committed round and any higher
	// round this node entered.
	Rounds []Round `json:"rounds,omitempty"`
	// Validators has a row for every member of the height's validator set
	// in the committed round, and in the other rounds for every member this
	// node received a message or evidence of.
	Validators []ValidatorRound `json:"validators,omitempty"`
}

// Round is one round of a height.
type Round struct {
	Round    string `json:"round"`
	Proposer string `json:"proposer"` // the proposer of the round by the proposer rule
	// Start is the start of the round of observe.md 4.1: the parent's time
	// plus the block period for round 0, this node's ROUND_ENTER for a
	// higher round; absent when unknown.
	Start *time.Time `json:"start,omitempty"`
	// Entered is the time of this node's ROUND_ENTER for the round.
	Entered *time.Time `json:"entered,omitempty"`
	// Cause is why this node entered the round (observe.md 2.3 item 7):
	// timeout, f_plus_one, finalize_fail or catch_up; absent for the start
	// of a sequence.
	Cause string `json:"cause,omitempty"`
	// Outcome is "committed" for the committed round, "round_change" for a
	// lower one, absent for a round above it.
	Outcome string `json:"outcome,omitempty"`
}

// ValidatorRound is one validator in one round of a height.
type ValidatorRound struct {
	Round      string `json:"round"`
	Validator  string `json:"validator"`
	Index      uint32 `json:"index"`
	IsProposer bool   `json:"isProposer,omitempty"`
	// The first arrival at this node of the validator's message of each
	// code in this round. For the node's own validator they are the node's
	// own messages (via "self").
	Preprepare  *Seen `json:"preprepare,omitempty"`
	Prepare     *Seen `json:"prepare,omitempty"`
	Commit      *Seen `json:"commit,omitempty"`
	RoundChange *Seen `json:"roundChange,omitempty"`
	// Header inclusion, in the committed round only: the height's own seals,
	// the prev seals of the next height, and Extra for a sealer that only
	// the next height's prev seals hold (a seal that came late).
	SealedPrepared  bool `json:"sealedPrepared,omitempty"`
	SealedCommitted bool `json:"sealedCommitted,omitempty"`
	InPrevPrepared  bool `json:"inPrevPrepared,omitempty"`
	InPrevCommitted bool `json:"inPrevCommitted,omitempty"`
	Extra           bool `json:"extra,omitempty"`
	// Evidence marks double-signing evidence of the validator in the round.
	Evidence bool `json:"evidence,omitempty"`
}

// Seen is the first arrival of a message.
type Seen struct {
	At time.Time `json:"at"`
	// DelayMs is At less the start of the round, when the start is known;
	// it may be negative for a message ahead of the start.
	DelayMs *int64 `json:"delayMs,omitempty"`
	Via     string `json:"via"` // direct, backlog or self
	Peer    string `json:"peer,omitempty"`
	Key     string `json:"key,omitempty"` // the message's dedup key
	Outcome string `json:"outcome"`       // ACCEPT or IGNORE
}

// Options configure a Recorder.
type Options struct {
	// KeepHeights is the number of heights kept below the newest; zero
	// keeps DefaultKeepHeights.
	KeepHeights uint64
	// Chain reads the headers; ValidatorsAt gives the validator set of a
	// height from its parent hash; Period gives the block period of a
	// height. Chain and ValidatorsAt are required.
	Chain        types.ChainReader
	ValidatorsAt func(types.Height, types.Hash) (*validator.Set, error)
	Period       func(types.Height) time.Duration
	// Dropped is called for every input dropped because the queue was full
	// and every record that could not be built or written
	// (wbft_participation_write_dropped_total).
	Dropped func()
	// Log receives write failures; nil discards them.
	Log *slog.Logger
}

const (
	// DefaultKeepHeights keeps about 28 hours of one-second blocks
	// (participation.md 4).
	DefaultKeepHeights = 100_000
	// queueLen bounds the inputs waiting for the recorder goroutine.
	queueLen = 8192
	// openHeights bounds the heights collected at once and the distance of
	// a message's height above the last finished one.
	openHeights = 16
	// messagesPerHeight bounds the first arrivals kept for one height.
	messagesPerHeight = 4096
	// backfillMax is the number of heights below an announced head that are
	// recorded with it when the application announced only the last of a
	// batch.
	backfillMax = 256
)

// input is one item of the queue: an event record or a new head.
type input struct {
	rec  event.Record
	at   event.Stamp
	head *types.Header
}

// Recorder builds the participation records from the event records and the
// new heads of a node and keeps them in a store (participation.md). Consume
// and Head do not block: their inputs go to a bounded queue that one
// goroutine works off. A height is recorded when the next height's header
// arrives: the prev seals of the next height are the record of a height's
// seals, the height's own seals only this node's view.
//
// Spec: WBFT-SEC-130
type Recorder struct {
	store *store
	opts  Options
	in    chan input
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once

	// Owned by the recorder goroutine.
	open     map[string]*building
	last     *big.Int      // the last height finished: recorded or given up
	prev     *types.Header // the last head, when it is the parent of the next
	prevHash types.Hash
}

// building collects the inputs of one height.
type building struct {
	local    bool
	entered  map[string]time.Time // round -> ROUND_ENTER
	causes   map[string]string    // round -> cause
	msgs     map[msgKey]Seen
	evidence map[rowKey]bool
}

type rowKey struct{ round, source string }

type msgKey struct {
	row  rowKey
	code uint64
}

// Open opens the store in dir and starts the recorder. The heights up to
// the chain's head are taken as finished: the head is recorded when its
// child arrives.
func Open(f fsys.FS, dir string, o Options) (*Recorder, error) {
	if o.KeepHeights == 0 {
		o.KeepHeights = DefaultKeepHeights
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	s, err := openStore(f, dir)
	if err != nil {
		return nil, err
	}
	r := &Recorder{store: s, opts: o, in: make(chan input, queueLen), stop: make(chan struct{}), done: make(chan struct{}),
		open: map[string]*building{}, last: big.NewInt(0)}
	if h := o.Chain.Head(); h != nil {
		r.last = new(big.Int).Sub(h.Number.Big(), big.NewInt(1))
		if r.last.Sign() < 0 {
			r.last.SetInt64(0)
		}
		r.prev, r.prevHash = h, codec.BlockHash(h)
	}
	go r.run()
	return r, nil
}

// Close stops the recorder after it worked off the queued inputs. The
// heights not yet recorded are lost.
func (r *Recorder) Close() {
	r.once.Do(func() { close(r.stop) })
	<-r.done
}

// Consume takes one event record (event.Writer.Observe).
func (r *Recorder) Consume(rec event.Record, at event.Stamp) {
	switch rec.Kind {
	case event.RoundEnter, event.MsgOutcome, event.Evidence:
		r.offer(input{rec: rec, at: at})
	}
}

// Head takes a new head of the application.
func (r *Recorder) Head(h *types.Header) {
	if h != nil {
		r.offer(input{head: h})
	}
}

func (r *Recorder) offer(in input) {
	select {
	case <-r.stop:
	case r.in <- in:
	default:
		r.dropped()
	}
}

func (r *Recorder) dropped() {
	if r.opts.Dropped != nil {
		r.opts.Dropped()
	}
}

// Range returns one record for every height from..to (participation.md 5).
func (r *Recorder) Range(from, to *big.Int) ([]Record, error) {
	return r.store.rangeOf(from, to)
}

func (r *Recorder) run() {
	defer close(r.done)
	for {
		select {
		case in := <-r.in:
			r.take(in)
		case <-r.stop:
			for {
				select {
				case in := <-r.in:
					r.take(in)
				default:
					return
				}
			}
		}
	}
}

func (r *Recorder) take(in input) {
	if in.head != nil {
		r.onHead(in.head)
		return
	}
	v := in.rec.View
	if v == nil {
		return
	}
	seq, ok := new(big.Int).SetString(v.Seq, 10)
	if !ok || seq.Cmp(r.last) <= 0 || new(big.Int).Sub(seq, r.last).Cmp(big.NewInt(openHeights)) > 0 {
		return
	}
	b := r.open[v.Seq]
	if b == nil {
		if len(r.open) >= openHeights {
			r.dropped()
			return
		}
		b = &building{entered: map[string]time.Time{}, causes: map[string]string{}, msgs: map[msgKey]Seen{}, evidence: map[rowKey]bool{}}
		r.open[v.Seq] = b
	}
	f := in.rec.Fields
	str := func(k string) string { s, _ := f[k].(string); return s }
	switch in.rec.Kind {
	case event.RoundEnter:
		b.local = true
		b.entered[v.Round] = in.at.Wall
		if c := roundCause(str("branch"), str("cause")); c != "" {
			b.causes[v.Round] = c
		}
	case event.MsgOutcome:
		code, ok := f["code"].(uint64)
		src := str("source")
		if !ok || src == "" || str("check") == "prefilter" || code < uint64(codec.CodePreprepare) || code > uint64(codec.CodeRoundChange) {
			return
		}
		b.local = true
		k := msgKey{row: rowKey{round: v.Round, source: src}, code: code}
		if _, ok := b.msgs[k]; ok {
			return
		}
		if len(b.msgs) >= messagesPerHeight {
			r.dropped()
			return
		}
		outcome, _ := f["outcome"].(event.OutcomeClass)
		b.msgs[k] = Seen{At: in.at.Wall, Via: str("via"), Peer: str("peer"), Key: str("dedup_key"), Outcome: string(outcome)}
	case event.Evidence:
		if src := str("source"); src != "" {
			b.local = true
			b.evidence[rowKey{round: v.Round, source: src}] = true
		}
	}
}

// roundCause is the round change cause of a ROUND_ENTER (observe.md 2.3
// item 7): the CATCH_UP branch counts as catch_up, the start of a sequence
// has none.
func roundCause(branch, cause string) string {
	switch {
	case cause == event.CauseStart || cause == event.CauseNewHead:
		return ""
	case branch == "CATCH_UP":
		return "catch_up"
	}
	return cause
}

// onHead records the heights below a new head that are not finished yet,
// oldest first, up to backfillMax of them.
func (r *Recorder) onHead(h *types.Header) {
	n := h.Number.Big()
	if n.Cmp(r.last) <= 0 {
		return
	}
	hash := codec.BlockHash(h)
	// hs[0] is h; hs[i+1] is the parent of hs[i].
	hs := []*types.Header{h}
	for cur := h; len(hs) <= backfillMax; {
		pn := new(big.Int).Sub(cur.Number.Big(), big.NewInt(1))
		if pn.Cmp(r.last) <= 0 {
			break
		}
		var p *types.Header
		if r.prev != nil && cur.ParentHash == r.prevHash {
			p = r.prev
		} else {
			p = r.opts.Chain.Header(cur.ParentHash, cur.Number.RefLow64()-1) //wbft:low64 HH-28
		}
		if p == nil {
			break
		}
		hs, cur = append(hs, p), p
	}
	for i := len(hs) - 1; i >= 1; i-- {
		r.finish(hs[i], hs[i-1])
	}
	r.last = new(big.Int).Sub(n, big.NewInt(1))
	r.prev, r.prevHash = h, hash
	for seq := range r.open { //wbft:unordered deleting from a map
		if s, ok := new(big.Int).SetString(seq, 10); !ok || s.Cmp(r.last) <= 0 {
			delete(r.open, seq)
		}
	}
	floor := new(big.Int).Sub(n, new(big.Int).SetUint64(r.opts.KeepHeights))
	if floor.Sign() > 0 {
		if err := r.store.prune(floor); err != nil {
			r.opts.Log.Warn("participation store prune failed", "err", err)
		}
	}
}

// finish builds and writes the record of h, whose child is child.
func (r *Recorder) finish(h, child *types.Header) {
	rec, err := r.build(h, child, r.open[h.Number.String()])
	if err == nil {
		err = r.store.put(h.Number.Big(), rec)
	}
	if err != nil {
		r.dropped()
		r.opts.Log.Warn("participation record not written", "height", h.Number.String(), "err", err)
	}
}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// build makes the record of h from its header, its child's prev seals and
// what the node collected for it (b, nil when nothing).
func (r *Recorder) build(h, child *types.Header, b *building) (*Record, error) {
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	vs, err := r.opts.ValidatorsAt(h.Number, h.ParentHash)
	if err != nil {
		return nil, err
	}
	hash := codec.BlockHash(h)
	rec := &Record{Height: h.Number.String(), Source: "header", Hash: "0x" + hex.EncodeToString(hash[:]),
		Round: big.NewInt(int64(x.Round)).String(), Proposer: hexAddr(h.Coinbase), Time: h.Time}
	if b != nil && b.local {
		rec.Source = "local"
	}
	var parent *types.Header
	if !h.Number.IsZero() {
		parent = r.opts.Chain.Header(h.ParentHash, h.Number.RefLow64()-1) //wbft:low64 HH-28
	}

	// The rounds: 0 to the committed round and any higher one entered.
	top := uint64(x.Round)
	if b != nil {
		for k := range b.entered { //wbft:unordered the maximum
			if v, ok := new(big.Int).SetString(k, 10); ok && v.IsUint64() && v.Uint64() > top && v.Uint64() < top+openHeights {
				top = v.Uint64()
			}
		}
	}
	starts := map[string]time.Time{}
	for i := uint64(0); i <= top; i++ {
		key := new(big.Int).SetUint64(i).String()
		rd := Round{Round: key}
		if p := vs.CalcProposer(types.ProposerOf(parent), i); p >= 0 {
			rd.Proposer = hexAddr(vs.At(p).Addr)
		}
		switch {
		case i == uint64(x.Round):
			rd.Outcome = "committed"
		case i < uint64(x.Round):
			rd.Outcome = "round_change"
		}
		if b != nil {
			if t, ok := b.entered[key]; ok {
				rd.Entered = &t
			}
			rd.Cause = b.causes[key]
		}
		switch {
		case i == 0 && parent != nil && r.opts.Period != nil:
			t := time.Unix(int64(parent.Time), 0).Add(r.opts.Period(h.Number)) //nolint:gosec // header times fit
			rd.Start = &t
		case i > 0 && rd.Entered != nil:
			rd.Start = rd.Entered
		}
		if rd.Start != nil {
			starts[key] = *rd.Start
		}
		rec.Rounds = append(rec.Rounds, rd)
	}

	// The rows: every member in the committed round, the others where the
	// node has a message or evidence of the member.
	rows := map[rowKey]*ValidatorRound{}
	row := func(round string, i int) *ValidatorRound {
		a := hexAddr(vs.At(i).Addr)
		k := rowKey{round: round, source: a}
		if v := rows[k]; v != nil {
			return v
		}
		v := &ValidatorRound{Round: round, Validator: a, Index: uint32(i)} //nolint:gosec // a set index
		for _, rd := range rec.Rounds {
			if rd.Round == round {
				v.IsProposer = rd.Proposer == a
			}
		}
		rows[k] = v
		return v
	}
	index := map[string]int{}
	for i := range vs.Len() {
		index[hexAddr(vs.At(i).Addr)] = i
	}
	committed := rec.Round
	for i := range vs.Len() {
		row(committed, i)
	}
	if b != nil {
		for k, s := range b.msgs { //wbft:unordered rows are sorted below
			i, ok := index[k.row.source]
			if !ok {
				continue
			}
			if st, ok := starts[k.row.round]; ok {
				d := s.At.Sub(st).Milliseconds()
				s.DelayMs = &d
			}
			v := row(k.row.round, i)
			switch codec.Code(k.code) {
			case codec.CodePreprepare:
				v.Preprepare = &s
			case codec.CodePrepare:
				v.Prepare = &s
			case codec.CodeCommit:
				v.Commit = &s
			case codec.CodeRoundChange:
				v.RoundChange = &s
			}
		}
		for k := range b.evidence { //wbft:unordered rows are sorted below
			if i, ok := index[k.source]; ok {
				row(k.round, i).Evidence = true
			}
		}
	}
	mark := func(s *types.AggregatedSeal, set func(*ValidatorRound)) map[uint32]bool {
		in := map[uint32]bool{}
		if s == nil {
			return in
		}
		for _, i := range s.Sealers.Sealers() {
			if int(i) < vs.Len() {
				in[i] = true
				set(row(committed, int(i)))
			}
		}
		return in
	}
	own := mark(x.PreparedSeal, func(v *ValidatorRound) { v.SealedPrepared = true })
	for i := range mark(x.CommittedSeal, func(v *ValidatorRound) { v.SealedCommitted = true }) { //wbft:unordered a set union
		own[i] = true
	}
	if cx, err := codec.DecodeExtra(child); err == nil {
		prev := mark(cx.PrevPreparedSeal, func(v *ValidatorRound) { v.InPrevPrepared = true })
		for i := range mark(cx.PrevCommittedSeal, func(v *ValidatorRound) { v.InPrevCommitted = true }) { //wbft:unordered a set union
			prev[i] = true
		}
		for i := range prev { //wbft:unordered flags commute
			if !own[i] {
				row(committed, int(i)).Extra = true
			}
		}
	}
	for _, v := range rows { //wbft:unordered rows are sorted below
		rec.Validators = append(rec.Validators, *v)
	}
	slices.SortFunc(rec.Validators, func(a, b ValidatorRound) int {
		ra, _ := new(big.Int).SetString(a.Round, 10)
		rb, _ := new(big.Int).SetString(b.Round, 10)
		if c := ra.Cmp(rb); c != 0 {
			return c
		}
		return int(a.Index) - int(b.Index)
	})
	return rec, nil
}
