package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/0xmhha/wbft/types"
)

// Stamp is what the caller knows about the moment of a record: the wall
// clock, the monotonic clock and, for records that belong to one input of the
// core, the input's step number.
type Stamp struct {
	Wall time.Time
	Mono time.Duration
	Step *uint64
}

// common are the field names the writer owns; a record must not use them.
var common = map[string]bool{
	"v": true, "node": true, "run": true, "seq": true, "t_wall": true,
	"t_mono_ns": true, "kind": true, "view": true, "step": true, "imp": true, "src": true,
}

// ErrReservedField is returned for a record whose Fields use a name of the
// common fields.
var ErrReservedField = errors.New("event: field name is reserved")

// Writer writes records as JSON Lines: one object per line with the common
// fields first (v, node, run, seq, t_wall, t_mono_ns, kind, view, step, imp,
// src) and the kind-specific fields after them in key order. The same records
// and stamps always produce the same bytes. A Writer is safe for concurrent
// use; seq increases by one per record within a run.
type Writer struct {
	mu   sync.Mutex
	w    io.Writer
	node string
	run  string
	seq  uint64
}

// NewWriter returns a writer for the node with address node in run run.
func NewWriter(w io.Writer, node types.Address, run string) *Writer {
	return &Writer{w: w, node: "0x" + fmt.Sprintf("%x", node[:]), run: run}
}

// Write stamps r and writes it as one line.
func (w *Writer) Write(r Record, at Stamp) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	line, err := encode(r, at, w.node, w.run, w.seq)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(line); err != nil {
		return err
	}
	w.seq++
	return nil
}

// Seq returns the sequence number the next record will get.
func (w *Writer) Seq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

func encode(r Record, at Stamp, node, run string, seq uint64) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	put := func(k string, v any) error {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshal(v)
		if err != nil {
			return fmt.Errorf("event: field %s: %w", k, err)
		}
		b.Write(vb)
		return nil
	}
	fields := []struct {
		k string
		v any
	}{
		{"v", Version},
		{"node", node},
		{"run", run},
		{"seq", seq},
		{"t_wall", at.Wall.UTC().Format(time.RFC3339Nano)},
		{"t_mono_ns", int64(at.Mono)},
		{"kind", string(r.Kind)},
	}
	for _, f := range fields {
		if err := put(f.k, f.v); err != nil {
			return nil, err
		}
	}
	if r.View != nil {
		if err := put("view", r.View); err != nil {
			return nil, err
		}
	}
	if at.Step != nil {
		if err := put("step", *at.Step); err != nil {
			return nil, err
		}
	}
	if len(r.Imp) > 0 {
		if err := put("imp", r.Imp); err != nil {
			return nil, err
		}
	}
	if r.Src != "" {
		if err := put("src", r.Src); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields { //wbft:unordered the keys are sorted below
		if common[k] {
			return nil, fmt.Errorf("%w: %s", ErrReservedField, k)
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := put(k, r.Fields[k]); err != nil {
			return nil, err
		}
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

// marshal encodes v without HTML escaping; maps are written with sorted keys
// by encoding/json.
func marshal(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}
