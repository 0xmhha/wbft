package metrics

import (
	"fmt"
	"math/big"
	"reflect"
	"sync"

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

	mu        sync.Mutex
	lastSeq   *big.Int // sequence of the last ROUND_ENTER
	lastRound float64
}

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
	}
}

// Observe updates the metrics from one event record.
func (m *EventMetrics) Observe(r event.Record, _ event.Stamp) {
	f := r.Fields
	switch r.Kind {
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
