package rpc

import (
	"encoding/json"
	"errors"
	"math/big"
)

// EventFilter is the filter of wbft_subscribe("events", filter)
// (observe.md 2.2): the kinds to deliver (every kind when empty) and a
// range of heights (the view's sequence), each bound optional. A record
// without a view (NODE_START, HEALTH, ...) is delivered only when neither
// bound is set.
type EventFilter struct {
	Kinds      []string   `json:"kinds,omitempty"`
	FromHeight *HeightArg `json:"fromHeight,omitempty"`
	ToHeight   *HeightArg `json:"toHeight,omitempty"`
}

// Check reports a filter whose range is empty.
func (f *EventFilter) Check() error {
	if f != nil && f.FromHeight != nil && f.ToHeight != nil && f.FromHeight.v.Cmp(f.ToHeight.v) > 0 {
		return errors.New("rpc: fromHeight is above toHeight")
	}
	return nil
}

// Match reports whether the event record rec passes the filter. A gap
// record (Gap) always passes. A nil filter passes everything.
func (f *EventFilter) Match(rec json.RawMessage) bool {
	if f == nil || len(f.Kinds) == 0 && f.FromHeight == nil && f.ToHeight == nil {
		return true
	}
	var h struct {
		Kind string                `json:"kind"`
		View *struct{ Seq string } `json:"view"`
		Gap  *json.RawMessage      `json:"gap"`
	}
	if json.Unmarshal(rec, &h) != nil {
		return false
	}
	if h.Gap != nil {
		return true
	}
	if len(f.Kinds) > 0 {
		found := false
		for _, k := range f.Kinds {
			if k == h.Kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.FromHeight == nil && f.ToHeight == nil {
		return true
	}
	if h.View == nil {
		return false
	}
	seq, ok := new(big.Int).SetString(h.View.Seq, 10)
	if !ok {
		return false
	}
	return (f.FromHeight == nil || seq.Cmp(f.FromHeight.v) >= 0) && (f.ToHeight == nil || seq.Cmp(f.ToHeight.v) <= 0)
}

// Gap is the record a subscription delivers when it dropped records
// because the subscriber did not keep up: the seq range of the records it
// dropped, matching the filter or not. wbft_events serves them while the
// node keeps them.
type Gap struct {
	Gap GapRange `json:"gap"`
}

// GapRange is the seq range of a Gap, both ends included.
type GapRange struct {
	FromSeq uint64 `json:"fromSeq"`
	ToSeq   uint64 `json:"toSeq"`
}
