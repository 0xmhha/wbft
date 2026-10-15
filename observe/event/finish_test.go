package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/types"
)

func TestFinishWaitsForEarlierRecordAndClosesObservers(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, types.Address{1}, "closed-run")
	entered, release := make(chan struct{}), make(chan struct{})
	observed := 0
	w.Observe(func(r Record, _ Stamp) {
		observed++
		if r.Kind == NodeStart {
			close(entered)
			<-release
		}
	})
	first := make(chan error, 1)
	go func() { first <- w.Write(Record{Kind: NodeStart}, Stamp{Wall: time.Unix(1, 0), Mono: 1}) }()
	<-entered
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	sampled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- w.Finish(Record{Kind: NodeStop}, func() Stamp { close(sampled); return Stamp{Wall: time.Unix(2, 0), Mono: 2} })
	}()
	select {
	case <-sampled:
		t.Error("terminal clock sampled before the preceding observer completed")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var writers sync.WaitGroup
	for range 16 {
		writers.Go(func() {
			if err := w.Write(Record{Kind: BuildFinished}, Stamp{Wall: time.Unix(3, 0), Mono: 3}); err != nil {
				t.Error(err)
			}
		})
	}
	writers.Wait()
	if err := w.Finish(Record{Kind: NodeStop}, func() Stamp { t.Error("repeated Finish sampled the clock"); return Stamp{} }); err != nil {
		t.Fatal(err)
	}
	if w.Seq() != 2 || observed != 2 {
		t.Fatalf("late records affected sequence or observers: %d/%d", w.Seq(), observed)
	}
	var kinds []Kind
	for line := range strings.Lines(buf.String()) {
		var r struct {
			Kind Kind  `json:"kind"`
			Mono int64 `json:"t_mono_ns"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, r.Kind)
		if r.Kind == NodeStop && r.Mono != 2 {
			t.Fatal("terminal clock lost", r)
		}
	}
	if len(kinds) != 2 || kinds[0] != NodeStart || kinds[1] != NodeStop {
		t.Fatal(kinds)
	}
}

type failedTerminalOutput struct{ bytes.Buffer }

var errTerminalOutput = errors.New("terminal output unavailable")

func (w *failedTerminalOutput) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"kind":"NODE_STOP"`)) {
		return 0, errTerminalOutput
	}
	return w.Buffer.Write(p)
}
func TestFailedFinishSealsTheRunWithoutClaimingARecordedBoundary(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "output failure", true: "invalid record"}[invalid], func(t *testing.T) {
			out := &failedTerminalOutput{}
			w := NewWriter(out, types.Address{}, "failed-end")
			observed := 0
			w.Observe(func(Record, Stamp) { observed++ })
			if err := w.Write(Record{Kind: NodeStart}, Stamp{}); err != nil {
				t.Fatal(err)
			}
			terminal := Record{Kind: NodeStop}
			want := errTerminalOutput
			if invalid {
				terminal.Fields = map[string]any{"seq": 1}
				want = ErrReservedField
			}
			if err := w.Finish(terminal, func() Stamp { return Stamp{} }); !errors.Is(err, want) {
				t.Fatalf("error %v, want %v", err, want)
			}
			if err := w.Write(Record{Kind: BuildFinished}, Stamp{}); err != nil {
				t.Fatal(err)
			}
			if w.Seq() != 1 || observed != 1 || bytes.Count(out.Bytes(), []byte("\n")) != 1 {
				t.Fatal("failed boundary became recorded or a late callback escaped")
			}
		})
	}
}
