package metrics

import (
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"time"

	"github.com/0xmhha/wbft/observe/event"
)

// Buckets of the event metrics.
var (
	roundBuckets   = []float64{0, 1, 2, 3, 5, 8, 13}
	secondsBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
)

// EventMetrics derives the metrics of observe.md 5.1 that the event stream
// carries from the node's event records; Observe takes each record as the
// event writer writes it. The other metrics of 5.1 are not derived here.
type EventMetrics struct {
	height, round               *Gauge
	roundChanges                *Counter
	heightRounds                *Histogram
	timerFires                  *Counter
	messages                    *Counter
	inboundDropped, disconnects *Counter
	appCall                     *Histogram
	evidence                    *Counter
	state                       *Gauge
	phase                       *Histogram
	slotOverwrites              *Counter

	mu        sync.Mutex
	lastSeq   *big.Int // sequence of the last ROUND_ENTER
	lastRound float64
	ph        phases
}

// States of wbft_consensus_state, in the order of the reference's State.
var stateValues = map[string]float64{"AcceptRequest": 0, "Preprepared": 1, "Prepared": 2, "Committed": 3}

// phases are the event times of the current view that wbft_phase_seconds
// measures between: the view's ROUND_ENTER, its PREPREPARE_ACCEPT, its
// PREPARE and COMMIT quorums, the FINALIZE_HANDOVER of its block and the
// NEW_HEAD of that block.
type phases struct {
	view                                   event.View
	enter, preprepare, prepared, committed mark
	handover                               mark
	number                                 string // block handed over, waiting for its NEW_HEAD
}

// mark is when a phase event happened in the view; ok is false until it has.
type mark struct {
	at time.Duration
	ok bool
}

// Phase names of wbft_phase_seconds: consecutive intervals of a view, so
// that they add up to the time from entering the view to the new head.
// preprepare includes the wait for the block period at round 0. commit is 0
// with this runner, which hands the block over in the step that decides it;
// import includes the application's finalize (wbft_app_call_seconds
// finalize_block measures that alone).
const (
	phasePreprepare    = "preprepare"     // ROUND_ENTER to PREPREPARE_ACCEPT
	phasePrepareQuorum = "prepare_quorum" // PREPREPARE_ACCEPT to the PREPARE quorum
	phaseCommitQuorum  = "commit_quorum"  // PREPARE quorum to the COMMIT quorum
	phaseCommit        = "commit"         // COMMIT quorum to FINALIZE_HANDOVER
	phaseImport        = "import"         // FINALIZE_HANDOVER to the block's NEW_HEAD
)

// NewEventMetrics registers the event metrics in r.
func NewEventMetrics(r *Registry) *EventMetrics {
	return &EventMetrics{
		height:         r.Gauge("wbft_consensus_height", "Sequence (block number) of the current view; inexact above 2^53."),
		round:          r.Gauge("wbft_consensus_round", "Round of the current view."),
		roundChanges:   r.Counter("wbft_round_changes_total", "Views entered at a round above 0, by cause.", "cause"),
		heightRounds:   r.Histogram("wbft_height_rounds", "Last round entered at a sequence, when the next sequence starts.", roundBuckets),
		timerFires:     r.Counter("wbft_timer_fires_total", "Timer expiries by timer and staleness.", "timer", "stale"),
		messages:       r.Counter("wbft_messages_total", "Consensus messages by code, direction and outcome (sent for outgoing).", "code", "dir", "outcome"),
		inboundDropped: r.Counter("wbft_peer_inbound_dropped_total", "Received messages dropped before the core, by reason.", "reason"),
		disconnects:    r.Counter("wbft_peer_inbound_disconnects_total", "Peers disconnected for overflowing their receive queue."),
		appCall:        r.Histogram("wbft_app_call_seconds", "Duration of application calls.", secondsBuckets, "method"),
		evidence:       r.Counter("wbft_evidence_total", "Evidence records by kind.", "kind"),
		state:          r.Gauge("wbft_consensus_state", "Consensus state: 0 AcceptRequest, 1 Preprepared, 2 Prepared, 3 Committed."),
		phase: r.Histogram("wbft_phase_seconds", "Consecutive phases of a view up to its block's new head: preprepare (with the block period wait), prepare_quorum, commit_quorum, commit, import (with the application's finalize).",
			secondsBuckets, "phase"),
		slotOverwrites: r.Counter("wbft_inbound_slot_overwrites_total", "Received messages replaced in their receive slot by a later one, by code.", "code"),
	}
}

// Observe updates the metrics from one event record.
func (m *EventMetrics) Observe(r event.Record, st event.Stamp) {
	f := r.Fields
	m.observePhase(r, st.Mono)
	switch r.Kind {
	case event.StateChange:
		if v, ok := stateValues[str(f["to"])]; ok {
			m.state.Set(v)
		}
	case event.RoundEnter:
		if r.View == nil {
			return
		}
		seq, ok1 := new(big.Int).SetString(r.View.Seq, 10)
		round, ok2 := new(big.Int).SetString(r.View.Round, 10)
		if !ok1 || !ok2 {
			return
		}
		rf, _ := new(big.Float).SetInt(round).Float64()
		sf, _ := new(big.Float).SetInt(seq).Float64()
		m.height.Set(sf)
		m.round.Set(rf)
		if round.Sign() > 0 {
			m.roundChanges.Inc(str(f["cause"]))
		}
		m.mu.Lock()
		if m.lastSeq != nil && seq.Cmp(m.lastSeq) > 0 {
			m.heightRounds.Observe(m.lastRound)
		}
		m.lastSeq, m.lastRound = seq, rf
		m.mu.Unlock()
	case event.TimerFire:
		m.timerFires.Inc(str(f["timer"]), str(f["stale"]))
	case event.MsgOutcome:
		m.messages.Inc(code(f["code"]), "in", str(f["outcome"]))
		if f["check"] == "prefilter" {
			m.inboundDropped.Inc(str(f["reason"]))
			if f["reason"] == "overwritten" {
				m.slotOverwrites.Inc(code(f["code"]))
			}
		}
	case event.Send:
		m.messages.Inc(code(f["code"]), "out", "sent")
	case event.Health:
		if f["what"] == "peer_inbound_disconnect" {
			m.disconnects.Inc()
		}
	case event.CommitResult:
		if ms, ok := f["duration_ms"].(int64); ok && ms >= 0 {
			m.appCall.Observe(float64(ms)/1000, "finalize_block")
		}
	case event.Evidence:
		m.evidence.Inc(str(f["evidence_kind"]))
	}
}

// observePhase marks the phase events of the current view at mono and
// observes each phase when its end is reached. A phase whose start was not
// seen in the view (a PREPARE quorum before the PRE-PREPARE was accepted,
// or a node started mid-view) is not observed.
func (m *EventMetrics) observePhase(r event.Record, mono time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := &m.ph
	in := r.View != nil && *r.View == p.view
	at := mark{mono, true}
	since := func(from mark, name string) {
		if from.ok && mono >= from.at {
			m.phase.Observe((mono - from.at).Seconds(), name)
		}
	}
	switch r.Kind {
	case event.RoundEnter:
		if r.View != nil {
			// The block handed over in the last view is imported while
			// the next one has started.
			*p = phases{view: *r.View, enter: at, handover: p.handover, number: p.number}
		}
	case event.PreprepareAccept:
		if in && !p.preprepare.ok {
			p.preprepare = at
			since(p.enter, phasePreprepare)
		}
	case event.Quorum:
		switch {
		case !in:
		case r.Fields["what"] == "PREPARE" && !p.prepared.ok:
			p.prepared = at
			since(p.preprepare, phasePrepareQuorum)
		case r.Fields["what"] == "COMMIT" && !p.committed.ok:
			p.committed = at
			since(p.prepared, phaseCommitQuorum)
		}
	case event.FinalizeHandover:
		if p.committed.ok && str(r.Fields["number"]) == p.view.Seq {
			since(p.committed, phaseCommit)
			p.handover, p.number = at, p.view.Seq
		}
	case event.NewHead:
		if p.number != "" && str(r.Fields["number"]) == p.number {
			since(p.handover, phaseImport)
			p.handover, p.number = mark{}, ""
		}
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// code is a message code as a label: 0x12 .. 0x15.
func code(v any) string {
	// Through reflect, so that a String method of a code type does not
	// change the label.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%#x", rv.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%#x", rv.Int())
	}
	return str(v)
}
