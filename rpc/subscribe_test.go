package rpc

import (
	"encoding/json"
	"testing"
)

// TestEventFilter reads a filter from its JSON and matches records by kind
// and by the view's sequence; a record without a view passes only without
// a height bound, and a gap record always passes.
func TestEventFilter(t *testing.T) {
	var f EventFilter
	if err := json.Unmarshal([]byte(`{"kinds":["ROUND_ENTER","COMMIT_DECIDED"],"fromHeight":"0xa","toHeight":12}`), &f); err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rec  string
		want bool
	}{
		{`{"seq":1,"kind":"ROUND_ENTER","view":{"seq":"10","round":"0"}}`, true},
		{`{"seq":2,"kind":"ROUND_ENTER","view":{"seq":"12","round":"3"}}`, true},
		{`{"seq":3,"kind":"ROUND_ENTER","view":{"seq":"9","round":"0"}}`, false},
		{`{"seq":4,"kind":"ROUND_ENTER","view":{"seq":"13","round":"0"}}`, false},
		{`{"seq":5,"kind":"MSG_OUTCOME","view":{"seq":"11","round":"0"}}`, false},
		{`{"seq":6,"kind":"ROUND_ENTER"}`, false},
		{`{"gap":{"fromSeq":7,"toSeq":9}}`, true},
		{`not json`, false},
	}
	for _, c := range cases {
		if got := f.Match(json.RawMessage(c.rec)); got != c.want {
			t.Errorf("%s: %v, want %v", c.rec, got, c.want)
		}
	}
	kinds := EventFilter{Kinds: []string{"HEALTH"}}
	if !kinds.Match(json.RawMessage(`{"kind":"HEALTH"}`)) || kinds.Match(json.RawMessage(`{"kind":"EVIDENCE"}`)) {
		t.Error("kinds only")
	}
	var none *EventFilter
	if !none.Match(json.RawMessage(`{"kind":"HEALTH"}`)) || none.Check() != nil {
		t.Error("nil filter")
	}
	if err := json.Unmarshal([]byte(`{"fromHeight":5,"toHeight":4}`), &f); err != nil || f.Check() == nil {
		t.Errorf("an empty range was accepted: %v", err)
	}
}
