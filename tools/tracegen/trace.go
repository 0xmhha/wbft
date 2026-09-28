package main

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// idRE matches a requirement ID such as WBFT-SM-041 or SNET-CFG-001.
var idRE = regexp.MustCompile(`\b(?:WBFT|SNET)-[A-Z]+-[0-9]{3}\b`)

// reqLineRE matches the line that starts a requirement in a specification
// chapter: "[WBFT-AREA-NNN] ...".
var reqLineRE = regexp.MustCompile(`^\[((?:WBFT|SNET)-[A-Z]+-[0-9]{3})\]`)

// Requirement is one requirement ID and where it was declared.
type Requirement struct {
	ID     string
	Source string // file the ID came from
}

// chapterGlob matches the chapter files of the specification, such as
// A-05-state-machine.md; other Markdown files (README, notes) are not read.
const chapterGlob = "[A-Z]-[0-9][0-9]-*.md"

// RequirementsFromSpec reads the requirement IDs declared in the chapters of
// a specification directory, in file and line order. This is the text
// conversion used when no structured speclint output is available.
func RequirementsFromSpec(dir string) ([]Requirement, error) {
	files, err := filepath.Glob(filepath.Join(dir, chapterGlob))
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	var reqs []Requirement
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			m := reqLineRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if seen[m[1]] {
				return nil, fmt.Errorf("%s: requirement %s declared twice", f, m[1])
			}
			seen[m[1]] = true
			reqs = append(reqs, Requirement{ID: m[1], Source: filepath.Base(f)})
		}
	}
	return reqs, nil
}

// RequirementsFromList reads requirement IDs from text: a plain list, or the
// text output of speclint. Every ID found is taken once, in order of first
// appearance.
func RequirementsFromList(r io.Reader, name string) ([]Requirement, error) {
	var reqs []Requirement
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		for _, id := range idRE.FindAllString(sc.Text(), -1) {
			if !seen[id] {
				seen[id] = true
				reqs = append(reqs, Requirement{ID: id, Source: name})
			}
		}
	}
	return reqs, sc.Err()
}

// VectorCase is one vector case directory <runner>/<handler>/<case>.
type VectorCase struct {
	Runner       string
	Handler      string
	Case         string
	Requirements []string
}

// HandlerName returns "<runner>/<handler>".
func (v VectorCase) HandlerName() string { return v.Runner + "/" + v.Handler }

// LoadVectors reads every <runner>/<handler>/<case>/meta.yaml under dir.
func LoadVectors(dir string) ([]VectorCase, error) {
	metas, err := filepath.Glob(filepath.Join(dir, "*", "*", "*", "meta.yaml"))
	if err != nil {
		return nil, err
	}
	slices.Sort(metas)
	cases := make([]VectorCase, 0, len(metas))
	for _, m := range metas {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, err
		}
		vc, err := parseMeta(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m, err)
		}
		cases = append(cases, vc)
	}
	return cases, nil
}

// Owner is one entry of owners.yaml.
type Owner struct {
	Owner   string // owning package(s) or party, comma-separated
	Symbols string // implementing functions, types or mechanisms, comma-separated
	Class   string // empty for wbft-owned; external, deployment, spec or withdrawn
	Reason  string // free text, e.g. why the owner is outside wbft
}

// CodeRef is a "// Spec:" or "// Covers:" reference in Go source.
type CodeRef struct {
	ID   string
	Pos  string // path:line relative to the scanned root
	Test bool   // "// Covers:" in a test file
}

var (
	specCommentRE   = regexp.MustCompile(`//\s*Spec:\s*(.*)$`)
	coversCommentRE = regexp.MustCompile(`//\s*Covers:\s*(.*)$`)
)

// ScanCode collects "// Spec: ID[, ID...]" comments from non-test Go files
// and "// Covers: ID[, ID...]" comments from test files under root. It skips
// testdata, vendor and hidden directories.
func ScanCode(root string) ([]CodeRef, error) {
	var refs []CodeRef
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		isTest := strings.HasSuffix(path, "_test.go")
		re := specCommentRE
		if isTest {
			re = coversCommentRE
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(data), "\n") {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			for _, id := range idRE.FindAllString(m[1], -1) {
				refs = append(refs, CodeRef{ID: id, Pos: filepath.ToSlash(rel) + ":" + strconv.Itoa(i+1), Test: isTest})
			}
		}
		return nil
	})
	return refs, err
}
