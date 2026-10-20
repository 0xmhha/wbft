package schema

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// TestKinds: the schema defines exactly the kinds that observe/event
// declares.
func TestKinds(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "../event.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, sp := range g.Specs {
			v := sp.(*ast.ValueSpec)
			if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Kind" {
				continue
			}
			for _, x := range v.Values {
				name, err := strconv.Unquote(x.(*ast.BasicLit).Value)
				if err != nil {
					t.Fatal(err)
				}
				declared = append(declared, name)
			}
		}
	}
	got := s.Kinds()
	slices.Sort(declared)
	slices.Sort(got)
	if len(declared) == 0 || !slices.Equal(got, declared) {
		t.Fatalf("schema kinds %v\nobserve/event kinds %v", got, declared)
	}
}

// TestRecords checks records the writer produces and hand-written ones.
func TestRecords(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := event.NewWriter(&buf, types.Address{0x37}, "run-1")
	step := uint64(3)
	at := event.Stamp{Wall: time.Unix(1_700_000_000, 5), Mono: 42, Step: &step}
	view := &event.View{Seq: "18446744073709551616", Round: "1"} // above 2^64
	hash := "0x" + strings.Repeat("ab", 32)
	addr := "0x" + strings.Repeat("cd", 20)
	good := []event.Record{
		{Kind: event.Health, Fields: map[string]any{"what": "same_block_transitions", "reason": "2 transitions at block 6 retain their configured application order"}},
		{Kind: event.BuildHandover, View: view, Fields: map[string]any{"build_id": "build-1", "number": view.Seq, "wait_ns": "0", "parent": hash}},
		{Kind: event.BuildStarted, View: view, Fields: map[string]any{"build_id": "build-1", "number": view.Seq}},
		{Kind: event.BuildFinished, View: view, Fields: map[string]any{"build_id": "build-1", "number": view.Seq, "status": "submitted", "hash": hash}},
		{Kind: event.BuildFinished, View: view, Fields: map[string]any{"build_id": "build-2", "number": view.Seq, "status": "replaced"}},
		{Kind: event.RoundEnter, View: view, Fields: map[string]any{"branch": "ROUND_CHANGE", "cause": event.CauseTimeout,
			"requested_round": "1", "proposer": addr, "is_proposer": false, "valset_digest": hash}},
		{Kind: event.MsgOutcome, View: view, Fields: map[string]any{"code": uint64(0x13), "check": nil, "outcome": event.Ignore,
			"row": 17, "via": "direct", "peer": addr, "dedup_key": hash}},
		{Kind: event.MsgOutcome, Fields: map[string]any{"code": uint64(0x13), "check": "prefilter", "outcome": event.DropSilent,
			"row": nil, "reason": "duplicate", "via": "direct", "peer": addr, "dedup_key": hash}},
		{Kind: event.NewHead, Fields: map[string]any{"number": "7", "hash": hash, "path": event.PathImported, "round": "0",
			"prepared_sealers": []uint32{0, 2}, "committed_sealers": []uint32{}}},
		{Kind: event.NodeStart, Fields: map[string]any{"refused": "sign state damaged"}},
		{Kind: event.NodeStart, Fields: map[string]any{"impl": "wbft", "mode": "embedded", "sign_floor": nil,
			"rule_activations": map[string]string{"committedEpochDiligence": "8", "epochInfoInProposal": "8", "firstProposerDiligenceCap": "10", "replayPerBlockPolicy": "12"},
			"wal_recovery":     map[string]any{"records": 0, "torn_bytes": 0, "corrupted": 0}}},
		{Kind: "MIRROR_MODE", Src: "app", Fields: map[string]any{"instance": "gov", "mode": "replay"}},
	}
	for _, r := range good {
		buf.Reset()
		if err := w.Write(r, at); err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(buf.Bytes()); err != nil {
			t.Errorf("%s: %v\n%s", r.Kind, err, buf.Bytes())
		}
	}
	if err := s.Validate([]byte(`{"v":1,"type":"dropped","node":"` + addr + `","run":"r","count":3,"from_seq":9}`)); err != nil {
		t.Errorf("dropped record: %v", err)
	}

	common := `"v":1,"node":"` + addr + `","run":"r","seq":0,"t_wall":"2026-10-11T00:00:00Z","t_mono_ns":0,`
	bad := []struct{ line, want string }{
		{`{` + common + `"kind":"BUILD_FINISHED","view":{"seq":"7","round":"0"},"build_id":"build-1","number":"7","status":"submitted"}`, "matches none"},
		{`{` + common + `"kind":"BUILD_STARTED","view":{"seq":"7","round":"0"},"build_id":"build-0","number":"7"}`, "does not match"},
		{`{` + common + `"kind":"NO_SUCH_KIND"}`, "none of the"},
		{`{` + common + `"kind":"NODE_STOP"}`, "lacks reason"},
		{`{` + common + `"kind":"NODE_STOP","reason":"operator","extra":1}`, "has extra"},
		{`{` + common + `"kind":"NODE_STOP","reason":"crash"}`, `/reason: "crash" is not one of`},
		{`{` + common + `"kind":"PROPOSAL_SUBMITTED","number":7}`, "/number: is number, not string"},
		{`{` + common + `"kind":"PROPOSAL_SUBMITTED","number":"07"}`, "does not match"},
		{`{` + common + `"kind":"NODE_START","impl":"wbft","mode":"embedded","sign_floor":null,"wal_recovery":{"records":0,"torn_bytes":0,"corrupted":0},"refused":"x"}`, "matches 2"},
		{`{` + common + `"kind":"COMMIT_RESULT","number":"1","hash":"` + hash + `","ok":true,"duration_ms":-1}`, "below 0"},
		{`{"v":1,"type":"dropped","node":"` + addr + `","run":"r","count":0,"from_seq":9}`, "below 1"},
		{`{"v":1,"node":"` + addr + `","run":"r","seq":0.5,"t_wall":"","t_mono_ns":0,"kind":"HEALTH","what":"disconnect"}`, "/seq: is number, not integer"},
	}
	for _, b := range bad {
		err := s.Validate([]byte(b.line))
		if err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s\n got %v, want %q", b.line, err, b.want)
		}
	}
}

// TestCompile refuses a schema the checker would not fully apply.
func TestCompile(t *testing.T) {
	for _, src := range []string{
		`{"format":"date-time"}`,
		`{"$ref":"#/$defs/missing"}`,
		`{"$ref":"other.json"}`,
		`{"unevaluatedProperties":{"type":"string"}}`,
		`{"type":"date"}`,
		`{"properties":{"a":{"if":{}}}}`,
	} {
		if _, err := Compile([]byte(src)); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: %v", src, err)
		}
	}
	s, err := Compile([]byte(`{"$defs":{"n":{"type":"integer","minimum":2}},"type":"array","items":{"$ref":"#/$defs/n"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`[2,3]`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`[2,1]`)); err == nil || !strings.Contains(err.Error(), "/1: 1 is below 2") {
		t.Fatal(err)
	}
}

func TestEngineReplayPolicyFieldsRemainOptionalAndTyped(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	prefix := `{"v":1,"kind":"ENGINE_START","node":"0x` + strings.Repeat("00", 20) + `","run":"r","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"engine_run":1,"reason":"start","replay":{"records":0,"stopped":null,"replayed":false`
	for _, suffix := range []string{`}}`, `,"enabled":true,"available":true}}`, `,"enabled":false,"available":true}}`, `,"enabled":true,"available":false}}`} {
		if err := s.Validate([]byte(prefix + suffix)); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{`,"enabled":"true"}}`, `,"available":1}}`, `,"enabled":null}}`, `,"extra":false}}`} {
		if err := s.Validate([]byte(prefix + suffix)); err == nil {
			t.Fatal("untyped or extra replay field accepted", suffix)
		}
	}
}
