package runner

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestCoreEventIdentityDistinguishesReusedStepNumbers(t *testing.T) {
	var buffer bytes.Buffer
	r := &Runner{d: Deps{Clock: &manualClock{}, Events: event.NewWriter(&buffer, types.Address{1}, "synthetic-writer")}}
	original := map[string]any{"what": "PREPARE", "count": 2, "quorum": 3}
	step := uint64(1)
	for _, generation := range []uint64{1, 2} {
		r.engineRun = generation
		r.emit(event.Record{Kind: event.Quorum, Fields: original}, &step)
	}
	if _, ok := original["engine_run"]; ok {
		t.Fatal("caller event fields were modified")
	}
	lines := bytes.Split(bytes.TrimSpace(buffer.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatal(len(lines))
	}
	for i, line := range lines {
		var record struct {
			Engine uint64 `json:"engine_run"`
			Step   uint64 `json:"step"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record.Engine != uint64(i+1) || record.Step != 1 {
			t.Fatal(record)
		}
	}
}
