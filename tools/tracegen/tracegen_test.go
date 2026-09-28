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
