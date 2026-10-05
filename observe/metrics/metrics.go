// Package metrics is the metric registry of a wbft node (observe.md 5): counters,
// gauges and histograms with labels, named by the Prometheus rules
// (wbft_<what>_<unit>), and their export in the Prometheus text exposition
// format. It depends on the standard library only; an application that has
// its own registry (go-ethereum's, for wbft-stablenet) can read the values
// through Gather.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Kinds of metrics.
const (
	KindCounter   = "counter"
	KindGauge     = "gauge"
	KindHistogram = "histogram"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// Registry holds metrics. It is safe for concurrent use.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]*metric
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{metrics: map[string]*metric{}} }

type metric struct {
	name, help, kind string
	labels           []string
	buckets          []float64 // histogram upper bounds, ascending, without +Inf
	mu               sync.Mutex
	series           map[string]*series
	collect          func() []Value // a gauge read when gathered
}

// Value is one series of a gauge read when gathered: its label values in
// the order of the labels, and its value.
type Value struct {
	Labels []string
	V      float64
}

type series struct {
	values []string
	value  float64  // counter, gauge
	counts []uint64 // histogram: per bucket (not cumulative), then +Inf
	sum    float64  // histogram
	count  uint64   // histogram
}

func (r *Registry) register(name, help, kind string, buckets []float64, labels []string) *metric {
	if !namePattern.MatchString(name) {
		panic(fmt.Sprintf("metrics: invalid name %q", name))
	}
	for _, l := range labels {
		if !namePattern.MatchString(l) || strings.HasPrefix(l, "__") || l == "le" {
			panic(fmt.Sprintf("metrics: invalid label %q of %s", l, name))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.metrics[name]; ok {
		if m.kind != kind || !slices.Equal(m.labels, labels) || !slices.Equal(m.buckets, buckets) {
			panic(fmt.Sprintf("metrics: %s registered twice with different definitions", name))
		}
		return m
	}
	m := &metric{name: name, help: help, kind: kind, labels: slices.Clone(labels), buckets: slices.Clone(buckets), series: map[string]*series{}}
	r.metrics[name] = m
	return m
}

// get returns the series of the label values, creating it.
func (m *metric) get(values []string) *series {
	if len(values) != len(m.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, got %d", m.name, len(m.labels), len(values)))
	}
	key := strings.Join(values, "\xff")
	s := m.series[key]
	if s == nil {
		s = &series{values: slices.Clone(values)}
		if m.kind == KindHistogram {
			s.counts = make([]uint64, len(m.buckets)+1)
		}
		m.series[key] = s
	}
	return s
}

// Counter is a monotonically increasing value.
type Counter struct{ m *metric }

// Counter registers (or returns) a counter.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{r.register(name, help, KindCounter, nil, labels)}
}

// Add adds v (>= 0) to the series of the label values.
func (c *Counter) Add(v float64, labelValues ...string) {
	if v < 0 || math.IsNaN(v) {
		panic(fmt.Sprintf("metrics: counter %s cannot add %v", c.m.name, v))
	}
	c.m.mu.Lock()
	c.m.get(labelValues).value += v
	c.m.mu.Unlock()
}

// Inc adds 1.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Gauge is a value that goes up and down.
type Gauge struct{ m *metric }

// Gauge registers (or returns) a gauge.
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	return &Gauge{r.register(name, help, KindGauge, nil, labels)}
}

// Set sets the series of the label values.
func (g *Gauge) Set(v float64, labelValues ...string) {
	g.m.mu.Lock()
	g.m.get(labelValues).value = v
	g.m.mu.Unlock()
}

// GaugeFunc registers a gauge whose series f returns each time the registry
// is gathered (a size or a queue length read from its owner). f must be
// quick and safe for concurrent use.
func (r *Registry) GaugeFunc(name, help string, labels []string, f func() []Value) {
	m := r.register(name, help, KindGauge, nil, labels)
	m.mu.Lock()
	m.collect = f
	m.mu.Unlock()
}

// Histogram counts observations in buckets.
type Histogram struct{ m *metric }

// Histogram registers (or returns) a histogram with the given ascending
// bucket upper bounds (+Inf is implied).
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if len(buckets) == 0 || !sort.Float64sAreSorted(buckets) {
		panic(fmt.Sprintf("metrics: histogram %s needs ascending buckets", name))
	}
	return &Histogram{r.register(name, help, KindHistogram, buckets, labels)}
}

// Observe records v in the series of the label values.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	h.m.mu.Lock()
	s := h.m.get(labelValues)
	i := sort.SearchFloat64s(h.m.buckets, v) // first bound >= v
	s.counts[i]++
	s.sum += v
	s.count++
	h.m.mu.Unlock()
}

// Sample is the value of one series at gathering time.
type Sample struct {
	Labels map[string]string
	Value  float64 // counter, gauge
	// Histogram: cumulative counts per upper bound (the last bound is
	// +Inf), sum and count.
	Buckets []Bucket
	Sum     float64
	Count   uint64
}

// Bucket is one cumulative histogram bucket.
type Bucket struct {
	UpperBound float64
	Count      uint64
}

// Family is one metric and its series.
type Family struct {
	Name, Help, Kind string
	Samples          []Sample
}

// Gather returns every metric in name order, each with its series in label
// order.
func (r *Registry) Gather() []Family {
	r.mu.Lock()
	ms := make([]*metric, 0, len(r.metrics))
	for _, m := range r.metrics { //wbft:unordered sorted below
		ms = append(ms, m)
	}
	r.mu.Unlock()
	sort.Slice(ms, func(i, j int) bool { return ms[i].name < ms[j].name })
	out := make([]Family, 0, len(ms))
	for _, m := range ms {
		m.mu.Lock()
		if m.collect != nil {
			f := m.collect
			m.mu.Unlock()
			vals := f() // outside the lock: f reads its owner
			m.mu.Lock()
			m.series = map[string]*series{}
			for _, v := range vals {
				m.get(v.Labels).value = v.V
			}
		}
		keys := make([]string, 0, len(m.series))
		for k := range m.series { //wbft:unordered sorted below
			keys = append(keys, k)
		}
		sort.Strings(keys)
		f := Family{Name: m.name, Help: m.help, Kind: m.kind}
		for _, k := range keys {
			s := m.series[k]
			smp := Sample{Labels: map[string]string{}, Value: s.value, Sum: s.sum, Count: s.count}
			for i, l := range m.labels {
				smp.Labels[l] = s.values[i]
			}
			if m.kind == KindHistogram {
				var cum uint64
				for i, b := range m.buckets {
					cum += s.counts[i]
					smp.Buckets = append(smp.Buckets, Bucket{UpperBound: b, Count: cum})
				}
				smp.Buckets = append(smp.Buckets, Bucket{UpperBound: math.Inf(1), Count: cum + s.counts[len(m.buckets)]})
			}
			f.Samples = append(f.Samples, smp)
		}
		m.mu.Unlock()
		out = append(out, f)
	}
	return out
}

// WriteText writes the registry in the Prometheus text exposition format
// (version 0.0.4), deterministically ordered.
func (r *Registry) WriteText(w io.Writer) error {
	var b strings.Builder
	for _, f := range r.Gather() {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Kind)
		for _, s := range f.Samples {
			labels := labelNames(s.Labels)
			if f.Kind != KindHistogram {
				fmt.Fprintf(&b, "%s%s %s\n", f.Name, labelText(s.Labels, labels, "", ""), formatFloat(s.Value))
				continue
			}
			for _, bk := range s.Buckets {
				fmt.Fprintf(&b, "%s_bucket%s %d\n", f.Name, labelText(s.Labels, labels, "le", formatFloat(bk.UpperBound)), bk.Count)
			}
			fmt.Fprintf(&b, "%s_sum%s %s\n", f.Name, labelText(s.Labels, labels, "", ""), formatFloat(s.Sum))
			fmt.Fprintf(&b, "%s_count%s %d\n", f.Name, labelText(s.Labels, labels, "", ""), s.Count)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Handler serves the registry in the text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WriteText(w)
	})
}

func labelNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m { //wbft:unordered sorted below
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func labelText(m map[string]string, names []string, extraName, extraValue string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	parts := make([]string, 0, len(names)+1)
	for _, n := range names {
		parts = append(parts, n+`="`+escapeValue(m[n])+`"`)
	}
	if extraName != "" {
		parts = append(parts, extraName+`="`+extraValue+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}
