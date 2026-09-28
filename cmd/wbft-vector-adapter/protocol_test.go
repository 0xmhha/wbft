package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var testImpl = Impl{Name: "wbft", Version: "test", Commit: "abc", Lang: "go", Build: "cgo"}

const runnerHello = `{"type":"hello","protocol":"wbft-vector/1","runner":{"name":"t","version":"0"},"spec_commit":"x"}`

// session runs serve over the given input lines and returns the exit status,
// the decoded output messages and the diagnostics.
func session(t *testing.T, lines ...string) (int, []map[string]any, string) {
	t.Helper()
	var out, diag bytes.Buffer
	code := serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, &diag, testImpl)
	var msgs []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout line is not a JSON object: %q: %v", l, err)
		}
		msgs = append(msgs, m)
	}
	return code, msgs, diag.String()
}

func TestHelloReply(t *testing.T) {
	code, msgs, _ := session(t, runnerHello, `{"type":"bye"}`)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	h := msgs[0]
	if h["type"] != "hello" || h["protocol"] != protocolName {
		t.Errorf("hello = %v", h)
	}
	impl := h["impl"].(map[string]any)
	if impl["build"] != "cgo" || impl["lang"] != "go" || impl["name"] != "wbft" {
		t.Errorf("impl = %v", impl)
	}
	if imp, ok := h["improvements"].([]any); !ok || len(imp) != 0 {
		t.Errorf("improvements = %#v, want empty list", h["improvements"])
	}
	hs := h["handlers"].([]any)
	if len(hs) != len(handlerNames()) {
		t.Errorf("handlers: %d listed, %d implemented", len(hs), len(handlerNames()))
	}
	for _, name := range hs {
		if handlers[name.(string)] == nil {
			t.Errorf("hello lists %v, which is not implemented", name)
		}
	}
	for i := 1; i < len(hs); i++ {
		if hs[i-1].(string) >= hs[i].(string) {
			t.Errorf("handlers not sorted: %v before %v", hs[i-1], hs[i])
		}
	}
}

func TestUnimplementedCasesUnsupported(t *testing.T) {
	lines := []string{runnerHello}
	var names []string
	for name, h := range handlers {
		if h == nil {
			names = append(names, name)
		}
	}
	names = append(names, "execution/process_finalize") // not listed: still answered
	for i, n := range names {
		r, h, _ := strings.Cut(n, "/")
		lines = append(lines, `{"type":"case","id":`+itoa(i+1)+`,"runner":"`+r+`","handler":"`+h+`","case":"c","kind":"pure","input":{"x":"0x00"}}`)
	}
	lines = append(lines, `{"type":"bye"}`)
	code, msgs, _ := session(t, lines...)
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if len(msgs) != len(names)+1 {
		t.Fatalf("got %d messages, want %d", len(msgs), len(names)+1)
	}
	for i, m := range msgs[1:] {
		if m["type"] != "result" || m["status"] != "unsupported" || m["id"] != float64(i+1) {
			t.Errorf("result %d = %v", i+1, m)
		}
		if _, ok := m["output"]; ok {
			t.Errorf("result %d has output", i+1)
		}
	}
}

func TestLargeIDEchoedVerbatim(t *testing.T) {
	var out, diag bytes.Buffer
	in := runnerHello + "\n" + `{"type":"case","id":123456789012345678901234567890,"runner":"crypto","handler":"keccak256","case":"c","kind":"pure","input":{}}` + "\n" + `{"type":"bye"}` + "\n"
	if code := serve(strings.NewReader(in), &out, &diag, testImpl); code != exitOK {
		t.Fatalf("exit = %d: %s", code, diag.String())
	}
	if !strings.Contains(out.String(), `"id":123456789012345678901234567890,`) {
		t.Errorf("id not echoed verbatim:\n%s", out.String())
	}
}

func TestProtocolErrors(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  int
	}{
		{"case before hello", []string{`{"type":"case","id":1,"runner":"a","handler":"b","case":"c","kind":"pure","input":{}}`}, exitProtocol},
		{"bye before hello", []string{`{"type":"bye"}`}, exitProtocol},
		{"not json", []string{runnerHello, `hello`}, exitProtocol},
		{"json array", []string{runnerHello, `[1]`}, exitProtocol},
		{"empty line", []string{runnerHello, ``}, exitProtocol},
		{"second hello", []string{runnerHello, runnerHello}, exitProtocol},
		{"unknown type", []string{runnerHello, `{"type":"ping"}`}, exitProtocol},
		{"fractional id", []string{runnerHello, `{"type":"case","id":1.5,"runner":"a","handler":"b","case":"c","kind":"pure","input":{}}`}, exitProtocol},
		{"string id", []string{runnerHello, `{"type":"case","id":"1","runner":"a","handler":"b","case":"c","kind":"pure","input":{}}`}, exitProtocol},
		{"missing handler", []string{runnerHello, `{"type":"case","id":1,"runner":"a","case":"c","kind":"pure","input":{}}`}, exitProtocol},
		{"eof before bye", []string{runnerHello}, exitEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, diag := session(t, tt.lines...)
			if code != tt.want {
				t.Errorf("exit = %d, want %d", code, tt.want)
			}
			if diag == "" {
				t.Error("no diagnostic on standard error")
			}
		})
	}
}

func TestProtocolMismatchStillAnswers(t *testing.T) {
	code, msgs, diag := session(t, `{"type":"hello","protocol":"wbft-vector/2"}`, `{"type":"bye"}`)
	if code != exitOK || len(msgs) != 1 || msgs[0]["protocol"] != protocolName {
		t.Fatalf("exit %d, msgs %v", code, msgs)
	}
	if !strings.Contains(diag, "wbft-vector/2") {
		t.Errorf("mismatch not reported: %q", diag)
	}
}

func TestNothingAfterBye(t *testing.T) {
	// Input after bye is not read or answered.
	code, msgs, _ := session(t, runnerHello, `{"type":"bye"}`, `not json`)
	if code != exitOK || len(msgs) != 1 {
		t.Fatalf("exit %d, %d messages", code, len(msgs))
	}
}

func TestHandlerOutcomes(t *testing.T) {
	const name = "test/handler"
	t.Cleanup(func() { delete(handlers, name) })
	run := func(h handler) map[string]any {
		t.Helper()
		handlers[name] = h
		_, msgs, _ := session(t, runnerHello,
			`{"type":"case","id":7,"runner":"test","handler":"handler","case":"c","kind":"pure","input":{"a":"1"}}`,
			`{"type":"bye"}`)
		if len(msgs) != 2 {
			t.Fatalf("got %d messages", len(msgs))
		}
		return msgs[1]
	}
	ok := run(func(kind string, in json.RawMessage) (any, error) {
		return map[string]string{"echo": string(in), "kind": kind}, nil
	})
	if ok["status"] != "ok" || ok["output"].(map[string]any)["kind"] != "pure" {
		t.Errorf("ok result = %v", ok)
	}
	failed := run(func(string, json.RawMessage) (any, error) { return nil, errors.New("trailing bytes") })
	if failed["status"] != "error" || failed["message"] != "trailing bytes" {
		t.Errorf("error result = %v", failed)
	}
	panicked := run(func(string, json.RawMessage) (any, error) { panic("boom") })
	if panicked["status"] != "error" {
		t.Errorf("panic result = %v", panicked)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
