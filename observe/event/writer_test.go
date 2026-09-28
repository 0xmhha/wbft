package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

func TestWriterLine(t *testing.T) {
	var buf bytes.Buffer
	node := types.Address{0x37, 0x6a}
	w := NewWriter(&buf, node, "run-1")
	step := uint64(7)
	at := Stamp{Wall: time.Unix(1700000000, 5).UTC(), Mono: 42 * time.Nanosecond, Step: &step}
	r := Record{
		Kind: MsgOutcome,
		View: ViewOf(types.View{Sequence: types.HeightFromUint64(10), Round: types.RoundFromUint64(1)}),
		Fields: map[string]any{
			"outcome": Accept,
			"code":    "19",
			"row":     17,
		},
	}
	if err := w.Write(r, at); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Record{Kind: Health, Fields: map[string]any{"what": "head_mismatch"}}, Stamp{Wall: at.Wall}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	want := `{"v":1,"node":"0x376a000000000000000000000000000000000000","run":"run-1","seq":0,` +
		`"t_wall":"2023-11-14T22:13:20.000000005Z","t_mono_ns":42,"kind":"MSG_OUTCOME",` +
		`"view":{"seq":"10","round":"1"},"step":7,"code":"19","outcome":"ACCEPT","row":17}`
	if lines[0] != want {
		t.Errorf("line 0:\n got %s\nwant %s", lines[0], want)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		t.Fatal(err)
	}
	if m["seq"] != float64(1) || m["kind"] != "HEALTH" {
		t.Errorf("line 1: %s", lines[1])
	}
	if _, ok := m["view"]; ok {
		t.Errorf("line 1 has a view: %s", lines[1])
	}
}

func TestWriterDeterministic(t *testing.T) {
	r := Record{Kind: Quorum, Fields: map[string]any{"what": "PREPARE", "count": 3, "quorum": 3, "z": []string{"a"}}}
	at := Stamp{Wall: time.Unix(0, 0)}
	var a, b bytes.Buffer
	for i := 0; i < 20; i++ {
		a.Reset()
		b.Reset()
		if err := NewWriter(&a, types.Address{}, "r").Write(r, at); err != nil {
			t.Fatal(err)
		}
		if err := NewWriter(&b, types.Address{}, "r").Write(r, at); err != nil {
			t.Fatal(err)
		}
		if a.String() != b.String() {
			t.Fatalf("different bytes:\n%s\n%s", a.String(), b.String())
		}
	}
}

func TestWriterReservedField(t *testing.T) {
	var buf bytes.Buffer
	err := NewWriter(&buf, types.Address{}, "r").Write(Record{Kind: Health, Fields: map[string]any{"seq": 1}}, Stamp{})
	if !errors.Is(err, ErrReservedField) {
		t.Fatalf("err = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %q", buf.String())
	}
}

// The spellings are shared with the vectors and the conformance tools.
func TestSpellings(t *testing.T) {
	for got, want := range map[OutcomeClass]string{Accept: "ACCEPT", Ignore: "IGNORE", DropSilent: "DROP_SILENT", Disconnect: "DISCONNECT", Pending: "PENDING"} {
		if string(got) != want {
			t.Errorf("%q != %q", got, want)
		}
	}
	causes := []SendCause{CauseBroadcast, CauseGossip, CauseRelay, CauseRetry, CauseReconnect, CauseReplay, CauseDirect}
	want := []string{"broadcast", "gossip", "relay", "retry", "reconnect", "replay", "direct"}
	for i, c := range causes {
		if string(c) != want[i] {
			t.Errorf("%q != %q", c, want[i])
		}
	}
}
