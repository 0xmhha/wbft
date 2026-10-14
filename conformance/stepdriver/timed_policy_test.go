package stepdriver

import (
	"encoding/json"
	"testing"
)

func TestTimerPolicyRefusesAmbiguousOrUnsupportedJSON(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `[]`, `{"request_timeout_seconds":1}`, `{"request_timeout_seconds":"0"}`, `{"request_timeout_seconds":"01"}`, `{"request_timeout_seconds":"+1"}`, `{"request_timeout_seconds":"1.0"}`, `{"request_timeout_seconds":"9223372037"}`, `{"request_timeout_seconds":"1","request_timeout_seconds":"2"}`, `{"retry_timeout_seconds":"1"}`, `{"max_request_timeout_seconds":null}`} {
		var p TimerPolicy
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Fatal("invalid policy accepted", raw)
		}
	}
	var p TimerPolicy
	raw := `{"request_timeout_seconds":"2","max_request_timeout_seconds":"0"}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if *p.RequestTimeoutSeconds != 2 || *p.MaxRequestTimeoutSeconds != 0 {
		t.Fatal(p)
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip TimerPolicy
	if err = json.Unmarshal(encoded, &roundTrip); err != nil || *roundTrip.RequestTimeoutSeconds != 2 || *roundTrip.MaxRequestTimeoutSeconds != 0 {
		t.Fatal(string(encoded), err)
	}
}
