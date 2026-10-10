package metrics

import (
	"bytes"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
)

// TestWriteText writes counters, gauges and histograms in the text format:
// families and series sorted, labels escaped, histogram buckets cumulative
// with le inclusive.
func TestWriteText(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("wbft_b_total", "B things.", "kind")
	c.Inc("y")
	c.Add(2, "x")
	c.Inc(`q"\` + "\n")
	g := r.Gauge("wbft_a", "A value.")
	g.Set(1.5)
	h := r.Histogram("wbft_c_seconds", "C durations.", []float64{0.1, 1}, "method")
	h.Observe(0.1, "m")
	h.Observe(0.5, "m")
	h.Observe(7, "m")
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP wbft_a A value.
# TYPE wbft_a gauge
wbft_a 1.5
# HELP wbft_b_total B things.
# TYPE wbft_b_total counter
wbft_b_total{kind="q\"\\\n"} 1
wbft_b_total{kind="x"} 2
wbft_b_total{kind="y"} 1
# HELP wbft_c_seconds C durations.
# TYPE wbft_c_seconds histogram
wbft_c_seconds_bucket{method="m",le="0.1"} 1
wbft_c_seconds_bucket{method="m",le="1"} 2
wbft_c_seconds_bucket{method="m",le="+Inf"} 3
wbft_c_seconds_sum{method="m"} 7.6
wbft_c_seconds_count{method="m"} 3
`
	if b.String() != want {
		t.Fatalf("text\n%s\nwant\n%s", b.String(), want)
	}
	// The handler serves the same text.
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Body.String() != want || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("handler %q %q", rec.Header().Get("Content-Type"), rec.Body.String())
	}
}

// TestRegisterRules returns the same metric for the same definition and
// refuses a different one, bad names, a wrong label count and a negative
// counter increment.
func TestRegisterRules(t *testing.T) {
	r := NewRegistry()
	a := r.Counter("wbft_x_total", "x", "l")
	a.Inc("1")
	r.Counter("wbft_x_total", "x", "l").Inc("1")
	if f := r.Gather(); f[0].Samples[0].Value != 2 {
		t.Fatalf("value %v", f[0].Samples[0].Value)
	}
	for name, f := range map[string]func(){
		"other kind":     func() { r.Gauge("wbft_x_total", "x", "l") },
		"other labels":   func() { r.Counter("wbft_x_total", "x", "m") },
		"bad name":       func() { r.Counter("wbft-x", "x") },
		"reserved label": func() { r.Counter("wbft_y", "y", "le") },
		"label count":    func() { a.Inc() },
		"negative":       func() { a.Add(-1, "1") },
		"no buckets":     func() { r.Histogram("wbft_h", "h", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func values(t *testing.T, r *Registry) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, f := range r.Gather() {
		for _, s := range f.Samples {
			k := f.Name
			for _, l := range labelNames(s.Labels) {
				k += " " + l + "=" + s.Labels[l]
			}
			if f.Kind == KindHistogram {
				out[k+" count"] = float64(s.Count)
				out[k+" sum"] = s.Sum
				continue
			}
			out[k] = s.Value
		}
	}
	return out
}

// TestEventMetrics derives the metrics from event records.
func TestEventMetrics(t *testing.T) {
	r := NewRegistry()
	m := NewEventMetrics(r)
	enter := func(seq, round, cause string) {
		m.Observe(event.Record{Kind: event.RoundEnter, View: &event.View{Seq: seq, Round: round}, Fields: map[string]any{"cause": cause}}, event.Stamp{})
	}
	enter("5", "0", "new_head")
	enter("5", "1", "timeout")
	enter("5", "2", "f_plus_one")
	enter("6", "0", "new_head") // sequence 5 ended at round 2
	m.Observe(event.Record{Kind: event.TimerFire, Fields: map[string]any{"timer": "round_change", "stale": false}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.MsgOutcome, Fields: map[string]any{"code": uint64(0x13), "outcome": "ACCEPT", "check": "PROCESS"}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.MsgOutcome, Fields: map[string]any{"code": uint64(0x14), "outcome": "DROP_SILENT", "check": "prefilter", "reason": "duplicate"}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.Send, Fields: map[string]any{"code": uint64(0x12), "cause": "broadcast"}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.Health, Fields: map[string]any{"what": "peer_inbound_disconnect"}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.CommitResult, Fields: map[string]any{"duration_ms": int64(250), "ok": true}}, event.Stamp{})
	m.Observe(event.Record{Kind: event.Evidence, Fields: map[string]any{"evidence_kind": "double_sign"}}, event.Stamp{})
	got := values(t, r)
	if _, ok := got["wbft_round_changes_total cause=new_head"]; ok {
		t.Error("a view at round 0 counted as a round change")
	}
	for k, v := range map[string]float64{
		"wbft_consensus_height":                                    6,
		"wbft_consensus_round":                                     0,
		"wbft_round_changes_total cause=timeout":                   1,
		"wbft_round_changes_total cause=f_plus_one":                1,
		"wbft_height_rounds count":                                 1,
		"wbft_height_rounds sum":                                   2,
		"wbft_timer_fires_total stale=false timer=round_change":    1,
		"wbft_messages_total code=0x13 dir=in outcome=ACCEPT":      1,
		"wbft_messages_total code=0x14 dir=in outcome=DROP_SILENT": 1,
		"wbft_messages_total code=0x12 dir=out outcome=sent":       1,
		"wbft_peer_inbound_dropped_total reason=duplicate":         1,
		"wbft_peer_inbound_disconnects_total":                      1,
		"wbft_app_call_seconds method=finalize_block count":        1,
		"wbft_app_call_seconds method=finalize_block sum":          0.25,
		"wbft_evidence_total kind=double_sign":                     1,
	} {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestEventPhases measures the consecutive phases of a view from the event
// times, the import of a block after the next view has started, the state
// gauge and slot overwrites; a quorum in a view whose PRE-PREPARE was not
// accepted is not a phase.
func TestEventPhases(t *testing.T) {
	r := NewRegistry()
	m := NewEventMetrics(r)
	ms := func(n int) event.Stamp { return event.Stamp{Mono: time.Duration(n) * time.Millisecond} }
	v5, v6 := &event.View{Seq: "5", Round: "0"}, &event.View{Seq: "6", Round: "1"}
	obs := func(k event.Kind, v *event.View, f map[string]any, at int) {
		m.Observe(event.Record{Kind: k, View: v, Fields: f}, ms(at))
	}
	obs(event.RoundEnter, v5, map[string]any{"cause": "new_head"}, 0) // the clock may start at 0
	obs(event.PreprepareAccept, v5, nil, 10)
	obs(event.StateChange, v5, map[string]any{"from": "AcceptRequest", "to": "Preprepared"}, 10)
	obs(event.Quorum, v5, map[string]any{"what": "PREPARE"}, 30)
	obs(event.Quorum, v5, map[string]any{"what": "PREPARE"}, 35) // a later report of the same quorum
	obs(event.Quorum, v5, map[string]any{"what": "COMMIT"}, 60)
	obs(event.StateChange, v5, map[string]any{"from": "Prepared", "to": "Committed"}, 60)
	obs(event.FinalizeHandover, nil, map[string]any{"number": "5"}, 70)
	obs(event.RoundEnter, v6, map[string]any{"cause": "timeout"}, 75)
	obs(event.NewHead, nil, map[string]any{"number": "5"}, 100)
	obs(event.Quorum, v6, map[string]any{"what": "PREPARE"}, 120) // no PRE-PREPARE accepted in view 6/1
	obs(event.MsgOutcome, nil, map[string]any{"code": uint64(0x13), "outcome": "DROP_SILENT", "check": "prefilter", "reason": "overwritten"}, 130)
	got := values(t, r)
	for k, v := range map[string]float64{
		"wbft_phase_seconds phase=preprepare sum":            0.010,
		"wbft_phase_seconds phase=prepare_quorum sum":        0.020,
		"wbft_phase_seconds phase=commit_quorum sum":         0.030,
		"wbft_phase_seconds phase=commit sum":                0.010,
		"wbft_phase_seconds phase=import sum":                0.030,
		"wbft_phase_seconds phase=prepare_quorum count":      1,
		"wbft_consensus_state":                               3,
		"wbft_inbound_slot_overwrites_total code=0x13":       1,
		"wbft_peer_inbound_dropped_total reason=overwritten": 1,
	} {
		if math.Abs(got[k]-v) > 1e-9 {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestGaugeFunc reads its series when the registry is gathered, and drops
// series that are no longer returned.
func TestGaugeFunc(t *testing.T) {
	r := NewRegistry()
	vals := []Value{{Labels: []string{"executable"}, V: 3}, {Labels: []string{"queued"}, V: 1}}
	r.GaugeFunc("wbft_pool_txs", "Pool.", []string{"list"}, func() []Value { return vals })
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `wbft_pool_txs{list="executable"} 3`) || !strings.Contains(b.String(), `wbft_pool_txs{list="queued"} 1`) {
		t.Fatalf("text %s", b.String())
	}
	vals = vals[:1]
	vals[0].V = 4
	b.Reset()
	_ = r.WriteText(&b)
	if !strings.Contains(b.String(), `wbft_pool_txs{list="executable"} 4`) || strings.Contains(b.String(), "queued") {
		t.Fatalf("text after a change %s", b.String())
	}
}

// TestDeleteWhere removes the series of one label value from a counter and
// a histogram and keeps the others; an unknown label removes nothing.
func TestDeleteWhere(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "", "validator", "type")
	h := r.Histogram("h_seconds", "", []float64{1}, "validator")
	c.Inc("a", "x")
	c.Inc("a", "y")
	c.Inc("b", "x")
	h.Observe(0.5, "a")
	h.Observe(0.5, "b")
	c.DeleteWhere("nope", "b")
	c.DeleteWhere("validator", "a")
	h.DeleteWhere("validator", "a")
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, `validator="a"`) || !strings.Contains(out, `c_total{type="x",validator="b"} 1`) ||
		!strings.Contains(out, `h_seconds_count{validator="b"} 1`) {
		t.Fatalf("after deleting a:\n%s", out)
	}
	c.Inc("a", "x") // a series can come back
	if got := r.Gather()[0].Samples; len(got) != 2 {
		t.Fatalf("series %v", got)
	}
}
