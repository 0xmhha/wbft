package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func ids(reqs []Requirement) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.ID
	}
	return out
}

func TestRequirementsFromSpec(t *testing.T) {
	reqs, err := RequirementsFromSpec("testdata/spec")
	if err != nil {
		t.Fatal(err)
	}
	// Only "[ID]" line starts of *.md chapters count, in file order.
	want := []string{"WBFT-TYPE-001", "WBFT-TYPE-002", "WBFT-VEC-033"}
	if got := ids(reqs); !slices.Equal(got, want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
	if reqs[2].Source != "A-11-fixture.md" {
		t.Errorf("source = %q", reqs[2].Source)
	}
}

func TestRequirementsFromList(t *testing.T) {
	text := "requirements: 3\nheader: WBFT-TYPE-001, WBFT-TYPE-002\nstate: WBFT-TYPE-001 WBFT-VEC-033\nnot-an-id: WBFT-TYPE-01 XWBFT-TYPE-0011\n"
	reqs, err := RequirementsFromList(strings.NewReader(text), "list")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"WBFT-TYPE-001", "WBFT-TYPE-002", "WBFT-VEC-033"}
	if got := ids(reqs); !slices.Equal(got, want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
}

func TestParseMeta(t *testing.T) {
	cases, err := LoadVectors("testdata/vectors")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range cases {
		got[c.HandlerName()+"/"+c.Case] = c.Requirements
	}
	want := map[string][]string{
		"crypto/keccak256/ascii":    {"WBFT-TYPE-001", "WBFT-TYPE-099"},
		"crypto/keccak256/empty":    {"WBFT-TYPE-001", "WBFT-TYPE-002"},
		"encoding/extra_codec/flow": {"WBFT-TYPE-002", "WBFT-VEC-033"},
	}
	if len(got) != len(want) {
		t.Fatalf("cases = %v", got)
	}
	for k, w := range want {
		if !slices.Equal(got[k], w) {
			t.Errorf("%s: requirements = %v, want %v", k, got[k], w)
		}
	}
}

func TestParseMetaErrors(t *testing.T) {
	for name, text := range map[string]string{
		"no handler":        "runner: crypto\ncase: c\n",
		"scalar list":       "runner: a\nhandler: b\nrequirements: WBFT-TYPE-001\n",
		"bad quote":         "runner: \"a\nhandler: b\n",
		"not a mapping key": "runner a\n",
	} {
		if _, err := parseMeta([]byte(text)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestParseOwnersErrors(t *testing.T) {
	for name, text := range map[string]string{
		"field before id": "  owner: types\n",
		"duplicate id":    "WBFT-TYPE-001:\n  owner: a\nWBFT-TYPE-001:\n  owner: b\n",
		"unknown field":   "WBFT-TYPE-001:\n  owners: a\n",
		"unknown class":   "WBFT-TYPE-001:\n  class: other\n",
		"deep indent":     "WBFT-TYPE-001:\n    owner: a\n",
	} {
		if _, _, err := ParseOwners(strings.NewReader(text)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestScanCode(t *testing.T) {
	refs, err := ScanCode("testdata/code")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		kind := "spec"
		if r.Test {
			kind = "covers"
		}
		got = append(got, kind+" "+r.ID+" "+r.Pos)
	}
	want := []string{
		"spec WBFT-TYPE-001 pkg/pkg.go:3",
		"spec WBFT-TYPE-002 pkg/pkg.go:3",
		"spec WBFT-TYPE-404 pkg/pkg.go:6",
		"covers WBFT-TYPE-001 pkg/pkg_test.go:3",
	}
	if !slices.Equal(got, want) {
		t.Errorf("refs =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRunCSV(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{
		"-spec", "testdata/spec",
		"-vectors", "testdata/vectors",
		"-owners", "testdata/owners.yaml",
		"-code", "testdata/code",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	want := `id,source,owner,symbols,class,code,tests,vector_handlers,vector_cases
WBFT-TYPE-001,A-01-fixture.md,types,"types.Address, types.Hash",,pkg/pkg.go:3,pkg/pkg_test.go:3,crypto/keccak256,2
WBFT-TYPE-002,A-01-fixture.md,,,,pkg/pkg.go:3,,crypto/keccak256 encoding/extra_codec,2
WBFT-VEC-033,A-11-fixture.md,cmd/wbft-vector-adapter,serve,external,,,encoding/extra_codec,1
`
	if out.String() != want {
		t.Errorf("csv =\n%s\nwant\n%s", out.String(), want)
	}
	for _, s := range []string{"vector: WBFT-TYPE-099 (crypto/keccak256/ascii)", "code: WBFT-TYPE-404 (pkg/pkg.go:6)"} {
		if !strings.Contains(errOut.String(), s) {
			t.Errorf("stderr lacks %q:\n%s", s, errOut.String())
		}
	}
}

func TestRunStrictAndFilters(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"-spec", "testdata/spec", "-vectors", "testdata/vectors", "-strict"}
	if code := run(args, &out, &errOut); code != 1 {
		t.Errorf("strict with unknown refs: exit = %d, want 1", code)
	}

	exclude := filepath.Join(t.TempDir(), "exclude.txt")
	writeFile(t, exclude, "WBFT-TYPE-002\n")
	out.Reset()
	errOut.Reset()
	code := run([]string{"-spec", "testdata/spec", "-prefix", "WBFT-TYPE-", "-exclude", exclude, "-format", "md"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[2], "| WBFT-TYPE-001 |") {
		t.Errorf("markdown =\n%s", out.String())
	}
}

func TestRunUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{},
		{"-spec", "testdata/spec", "-requirements", "x"},
		{"-spec", "testdata/spec", "-format", "xml"},
	} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	entries := []BaselineEntry{
		{ID: "WBFT-TYPE-001", Handlers: []string{"crypto/keccak256"}},
		{ID: "WBFT-TYPE-002"},
		{ID: "WBFT-VEC-033", Handlers: []string{"crypto/keccak256", "encoding/extra_codec"}},
	}
	var buf bytes.Buffer
	if err := WriteBaseline(&buf, entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\nWBFT-TYPE-002\t\n") {
		t.Errorf("empty handler column not kept:\n%s", buf.String())
	}
	got, err := ReadBaseline(&buf, "rt")
	if err != nil {
		t.Fatal(err)
	}
	if diff := CompareBaseline(entries, got); len(diff) != 0 {
		t.Errorf("round trip differs: %v", diff)
	}
}

func TestReadBaselineErrors(t *testing.T) {
	for name, text := range map[string]string{
		"not an id":      "WBFT-TYPE-01\tcrypto/keccak256\n",
		"id with suffix": "WBFT-TYPE-001x\t\n",
		"duplicate id":   "WBFT-TYPE-001\t\nWBFT-TYPE-001\tcrypto/keccak256\n",
		"bad handler":    "WBFT-TYPE-001\tkeccak256\n",
		"deep handler":   "WBFT-TYPE-001\tcrypto/keccak256/empty\n",
	} {
		if _, err := ReadBaseline(strings.NewReader(text), name); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCompareBaseline(t *testing.T) {
	want := []BaselineEntry{
		{ID: "WBFT-TYPE-001", Handlers: []string{"crypto/keccak256"}},
		{ID: "WBFT-TYPE-002", Handlers: []string{"crypto/keccak256", "encoding/extra_codec"}},
		{ID: "WBFT-VEC-033", Handlers: []string{"encoding/extra_codec"}},
	}
	got := []BaselineEntry{
		{ID: "WBFT-TYPE-001", Handlers: []string{"crypto/keccak256"}},
		{ID: "WBFT-TYPE-002", Handlers: []string{"encoding/extra_codec", "encoding/message_codec"}},
		{ID: "WBFT-TYPE-003"},
	}
	wantDiff := []string{
		"~ WBFT-TYPE-002  handlers: +encoding/message_codec -crypto/keccak256",
		"+ WBFT-TYPE-003  requirement not in the baseline (handlers: none)",
		"- WBFT-VEC-033  requirement in the baseline but not in the matrix",
	}
	if diff := CompareBaseline(want, got); !slices.Equal(diff, wantDiff) {
		t.Errorf("diff =\n%s\nwant\n%s", strings.Join(diff, "\n"), strings.Join(wantDiff, "\n"))
	}
	if diff := CompareBaseline(want, want); len(diff) != 0 {
		t.Errorf("equal entries: diff = %v", diff)
	}
}

func TestRunBaseline(t *testing.T) {
	sources := []string{"-spec", "testdata/spec", "-vectors", "testdata/vectors", "-o", os.DevNull}
	var out, errOut bytes.Buffer

	// The committed fixture matches the fixture sources.
	if code := run(append(sources, "-baseline", "testdata/baseline.tsv"), &out, &errOut); code != 0 {
		t.Fatalf("matching baseline: exit = %d: %s", code, errOut.String())
	}

	// -write-baseline reproduces a file that compares equal.
	path := filepath.Join(t.TempDir(), "baseline.tsv")
	errOut.Reset()
	if code := run(append(sources, "-write-baseline", path), &out, &errOut); code != 0 {
		t.Fatalf("write: exit = %d: %s", code, errOut.String())
	}
	errOut.Reset()
	if code := run(append(sources, "-baseline", path), &out, &errOut); code != 0 {
		t.Fatalf("written baseline: exit = %d: %s", code, errOut.String())
	}

	// Drift in the requirement list and the handler column fails with a diff.
	writeFile(t, path, "WBFT-TYPE-001\tcrypto/keccak256\nWBFT-TYPE-002\tcrypto/keccak256\nWBFT-TYPE-005\t\n")
	errOut.Reset()
	if code := run(append(sources, "-baseline", path), &out, &errOut); code != 1 {
		t.Fatalf("drift: exit = %d, want 1: %s", code, errOut.String())
	}
	for _, s := range []string{
		"~ WBFT-TYPE-002  handlers: +encoding/extra_codec",
		"+ WBFT-VEC-033  requirement not in the baseline (handlers: encoding/extra_codec)",
		"- WBFT-TYPE-005  requirement in the baseline but not in the matrix",
		"3 differences",
	} {
		if !strings.Contains(errOut.String(), s) {
			t.Errorf("stderr lacks %q:\n%s", s, errOut.String())
		}
	}

	// A missing or malformed baseline is a usage error, not drift.
	errOut.Reset()
	if code := run(append(sources, "-baseline", filepath.Join(t.TempDir(), "none.tsv")), &out, &errOut); code != 2 {
		t.Errorf("missing baseline: exit = %d, want 2", code)
	}
	if code := run(append(sources, "-baseline", path, "-write-baseline", path), &out, &errOut); code != 2 {
		t.Errorf("both flags: exit = %d, want 2", code)
	}
}

func TestCheck(t *testing.T) {
	m := Matrix{Rows: []Row{
		// Complete by vector.
		{ID: "WBFT-TYPE-001", Source: "A-01-x.md", Owner: "types", Symbols: "types.Hash", Code: []string{"types/hash.go:3"}, Handlers: []string{"crypto/keccak256"}},
		// Complete by test; unqualified symbol in an owner package.
		{ID: "WBFT-TYPE-002", Source: "A-01-x.md", Owner: "types, codec", Symbols: "X.M", Code: []string{"codec/x.go:9"}, Tests: []string{"codec/x_test.go:4"}},
		// Unimplemented handler, no test; comment outside the owner;
		// undeclared symbol.
		{ID: "WBFT-TYPE-003", Source: "A-01-x.md", Owner: "types", Symbols: "types.Y", Code: []string{"header/y.go:1"}, Handlers: []string{"execution/run"}},
		// Unknown owner package, no symbols, no code, no evidence.
		{ID: "WBFT-TYPE-004", Source: "A-01-x.md", Owner: "nosuch"},
		// Out of scope: classed, or another chapter.
		{ID: "WBFT-TYPE-005", Source: "A-01-x.md", Class: "external"},
		{ID: "WBFT-SM-001", Source: "A-05-x.md", Owner: "consensus"},
	}}
	decls := Decls{
		Name: map[string]string{"types": "types", "codec": "codec", "header": "header"},
		Names: map[string]map[string]bool{
			"types": {"Hash": true}, "codec": {"X": true, "X.M": true}, "header": {"Y": true},
		},
	}
	res := Check(m, []string{"A-01", "A-02"}, map[string]bool{"crypto/keccak256": true}, decls)
	if res.Checked != 4 || res.ByVector != 1 || res.ByTest != 1 {
		t.Errorf("checked=%d by_vector=%d by_test=%d, want 4 1 1", res.Checked, res.ByVector, res.ByTest)
	}
	var got []string
	for _, g := range res.Gaps {
		got = append(got, g.ID+" "+g.Kind)
	}
	want := []string{
		"WBFT-TYPE-003 symbols", "WBFT-TYPE-003 code", "WBFT-TYPE-003 evidence",
		"WBFT-TYPE-004 owner", "WBFT-TYPE-004 symbols", "WBFT-TYPE-004 code", "WBFT-TYPE-004 evidence",
	}
	if !slices.Equal(got, want) {
		t.Errorf("gaps = %v, want %v", got, want)
	}
	if res.Complete() {
		t.Error("Complete() = true with gaps")
	}
	if s := res.Summary(); !strings.Contains(s, "checked=4 complete=2 by_vector=1 by_test=1 incomplete=2 gaps=7") {
		t.Errorf("summary = %q", s)
	}
}

func TestScanDecls(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"a/a.go":      "package a\n\ntype T struct{ F int }\n\ntype I interface{ M() }\n\nfunc (t *T) Get() int { return t.F }\n\nfunc New() T { return T{} }\n\nconst C = 1\n\nvar V, W int\n",
		"b/src/s.go":  "package source\n\nfunc Load() {}\n",
		"b/b_test.go": "package b\n\nfunc TestOnly() {}\n",
		"c/c.txt":     "not go",
	}
	for f, text := range files {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d, err := ScanDecls(root)
	if err != nil {
		t.Fatal(err)
	}
	for pkg, want := range map[string]bool{"a": true, "b/src": true, "b": false, "c": false} {
		if got := d.IsPackage(pkg); got != want {
			t.Errorf("IsPackage(%q) = %v, want %v", pkg, got, want)
		}
	}
	for sym, want := range map[string]bool{
		"a.T": true, "a.T.F": true, "a.T.Get": true, "a.I.M": true, "a.New": true, "a.C": true, "a.W": true,
		"source.Load": true, "a.Missing": false, "b.TestOnly": false, "T.Get": true, "Load": false,
	} {
		if got := d.Resolve(sym, []string{"a"}); got != want {
			t.Errorf("Resolve(%q) = %v, want %v", sym, got, want)
		}
	}
}

func TestAdapterHandlers(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "adapter")
	hello := `{"type":"hello","protocol":"wbft-vector/1","handlers":["crypto/keccak256","header/verify_light"]}`
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\necho '"+hello+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := AdapterHandlers(script)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["crypto/keccak256"] || !got["header/verify_light"] {
		t.Errorf("handlers = %v", got)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho '{\"type\":\"result\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := AdapterHandlers(bad); err == nil {
		t.Error("no error for a bad hello")
	}
}

func TestReadHandlers(t *testing.T) {
	f := filepath.Join(t.TempDir(), "h.txt")
	if err := os.WriteFile(f, []byte("a/b, c/d\ne/f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readHandlers(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got["a/b"] || !got["c/d"] || !got["e/f"] {
		t.Errorf("handlers = %v", got)
	}
}
