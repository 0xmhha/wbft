package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// The check mode (-check) decides whether every wbft-owned requirement of the
// given chapters is implemented and has evidence:
//
//   - owner: every package named in owners.yaml exists under the code root;
//   - symbols: owners.yaml names the implementing symbols, and each is
//     declared in the code ("pkg.Name", "pkg.Type.Method", or unqualified in
//     an owner package);
//   - code: a "// Spec: ID" comment sits in a non-test file of an owner
//     package (a comment only in another package means the owner is wrong);
//   - evidence: a vector handler that cites the ID is implemented by the
//     adapter (its cases then run in the conformance step of CI, which fails
//     on any failed case), or, for a requirement without such a handler, a
//     test file carries a "// Covers: ID" comment.
//
// Requirements with a class (external, deployment, spec, withdrawn) are not
// checked.

// Gap is one missing piece of a checked requirement.
type Gap struct {
	ID     string
	Source string
	Kind   string // owner, symbols, code or evidence
	Detail string
}

func (g Gap) String() string {
	return fmt.Sprintf("%s (%s): %s: %s", g.ID, g.Source, g.Kind, g.Detail)
}

// CheckResult is the outcome of the check mode.
type CheckResult struct {
	Checked    int // requirements in scope
	ByVector   int // evidence from an implemented vector handler
	ByTest     int // evidence from a "// Covers:" test only
	Gaps       []Gap
	GapsByKind map[string]int
}

// Complete reports whether no checked requirement has a gap.
func (r CheckResult) Complete() bool { return len(r.Gaps) == 0 }

// Summary returns counts for a one-line report.
func (r CheckResult) Summary() string {
	failing := map[string]bool{}
	for _, g := range r.Gaps {
		failing[g.ID] = true
	}
	return fmt.Sprintf("checked=%d complete=%d by_vector=%d by_test=%d incomplete=%d gaps=%d (owner=%d symbols=%d code=%d evidence=%d)",
		r.Checked, r.Checked-len(failing), r.ByVector, r.ByTest, len(failing), len(r.Gaps),
		r.GapsByKind["owner"], r.GapsByKind["symbols"], r.GapsByKind["code"], r.GapsByKind["evidence"])
}

// Check runs the check mode on the rows of m whose source chapter starts with
// one of chapters (for example "A-01"). handlers is the set of
// "<runner>/<handler>" the adapter implements; decls are the declarations of
// the code root, against which owner packages and symbols are resolved.
func Check(m Matrix, chapters []string, handlers map[string]bool, decls Decls) CheckResult {
	res := CheckResult{GapsByKind: map[string]int{}}
	add := func(r Row, kind, detail string) {
		res.Gaps = append(res.Gaps, Gap{ID: r.ID, Source: r.Source, Kind: kind, Detail: detail})
		res.GapsByKind[kind]++
	}
	for _, r := range m.Rows {
		if r.Class != "" || !inChapters(r.Source, chapters) {
			continue
		}
		res.Checked++
		owners := splitList(r.Owner)
		if len(owners) == 0 {
			add(r, "owner", "no owner in owners.yaml")
		}
		for _, o := range owners {
			if !decls.IsPackage(o) {
				add(r, "owner", fmt.Sprintf("owner %q is not a package of the code root", o))
			}
		}
		symbols := splitList(r.Symbols)
		if len(symbols) == 0 {
			add(r, "symbols", "no symbols in owners.yaml")
		}
		for _, sym := range symbols {
			if !decls.Resolve(sym, owners) {
				add(r, "symbols", fmt.Sprintf("symbol %s is not declared", sym))
			}
		}
		switch {
		case len(r.Code) == 0:
			add(r, "code", "no // Spec: comment")
		case !slices.ContainsFunc(r.Code, func(pos string) bool { return inPackages(pos, owners) }):
			add(r, "code", fmt.Sprintf("// Spec: comments only outside the owner packages (%s)", strings.Join(r.Code, " ")))
		}
		switch {
		case slices.ContainsFunc(r.Handlers, func(h string) bool { return handlers[h] }):
			res.ByVector++
		case len(r.Tests) > 0:
			res.ByTest++
		case len(r.Handlers) > 0:
			add(r, "evidence", fmt.Sprintf("the adapter implements none of the handlers %s and no test has // Covers:", strings.Join(r.Handlers, " ")))
		default:
			add(r, "evidence", "no vector handler and no test with // Covers:")
		}
	}
	return res
}

func inChapters(source string, chapters []string) bool {
	return slices.ContainsFunc(chapters, func(c string) bool { return strings.HasPrefix(source, c+"-") || source == c })
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// inPackages reports whether the file of pos ("dir/file.go:line") lies
// directly in one of the package directories pkgs.
func inPackages(pos string, pkgs []string) bool {
	file, _, _ := strings.Cut(pos, ":")
	dir := path.Dir(file)
	return slices.Contains(pkgs, dir)
}

// AdapterHandlers starts a vector adapter (wbft-vector/1), exchanges hello
// and bye and returns the handlers it announces.
func AdapterHandlers(command string) (map[string]bool, error) {
	cmd := exec.Command(command)
	cmd.Stdin = strings.NewReader(
		`{"type":"hello","protocol":"wbft-vector/1","runner":{"name":"tracegen","version":"0"},"spec_commit":"none"}` + "\n" +
			`{"type":"bye"}` + "\n")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("adapter %s: %w", command, err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	var hello struct {
		Type     string   `json:"type"`
		Protocol string   `json:"protocol"`
		Handlers []string `json:"handlers"`
	}
	if err := json.Unmarshal([]byte(line), &hello); err != nil {
		return nil, fmt.Errorf("adapter %s: bad hello: %w", command, err)
	}
	if hello.Type != "hello" || hello.Protocol != "wbft-vector/1" {
		return nil, fmt.Errorf("adapter %s: bad hello %q", command, line)
	}
	set := map[string]bool{}
	for _, h := range hello.Handlers {
		set[h] = true
	}
	return set, nil
}

// readHandlers reads handler names, one per line or separated by spaces or
// commas, from a file.
func readHandlers(file string) (map[string]bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		for _, h := range strings.FieldsFunc(sc.Text(), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			set[h] = true
		}
	}
	return set, sc.Err()
}

// Decls holds the top-level declarations of the Go packages under a root:
// for each package directory (slash-separated, relative to the root) its
// package name and the declared names ("Name" for functions, types,
// variables and constants, "Type.Method" for methods).
type Decls struct {
	Name  map[string]string          // directory -> package name
	Names map[string]map[string]bool // directory -> declared names
}

// ScanDecls parses the non-test Go files under root (skipping testdata,
// vendor and hidden directories) and collects their declarations.
func ScanDecls(root string) (Decls, error) {
	d := Decls{Name: map[string]string{}, Names: map[string]map[string]bool{}}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			name := e.Name()
			if p != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		dir := filepath.ToSlash(rel)
		d.Name[dir] = f.Name.Name
		names := d.Names[dir]
		if names == nil {
			names = map[string]bool{}
			d.Names[dir] = names
		}
		for _, decl := range f.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil || len(decl.Recv.List) == 0 {
					names[decl.Name.Name] = true
					continue
				}
				if recv := recvName(decl.Recv.List[0].Type); recv != "" {
					names[recv+"."+decl.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range decl.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						names[s.Name.Name] = true
						addFields(names, s)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							names[n.Name] = true
						}
					}
				}
			}
		}
		return nil
	})
	return d, err
}

// addFields records the fields of a struct type and the methods of an
// interface type as "Type.Name".
func addFields(names map[string]bool, s *ast.TypeSpec) {
	var list *ast.FieldList
	switch t := s.Type.(type) {
	case *ast.StructType:
		list = t.Fields
	case *ast.InterfaceType:
		list = t.Methods
	}
	if list == nil {
		return
	}
	for _, f := range list.List {
		for _, n := range f.Names {
			names[s.Name.Name+"."+n.Name] = true
		}
	}
}

func recvName(e ast.Expr) string {
	for {
		switch t := e.(type) {
		case *ast.StarExpr:
			e = t.X
		case *ast.IndexExpr:
			e = t.X
		case *ast.IndexListExpr:
			e = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// Resolve reports whether symbol is declared. A symbol "pkg.Name" or
// "pkg.Type.Method" is looked up in the packages named pkg (preferring the
// owner directories); an unqualified "Name" or "Type.Method" is looked up in
// the owner directories.
func (d Decls) Resolve(symbol string, owners []string) bool {
	if first, rest, ok := strings.Cut(symbol, "."); ok {
		for dir, name := range d.Name {
			if name == first && d.Names[dir][rest] {
				return true
			}
		}
	}
	for _, o := range owners {
		if d.Names[o][symbol] {
			return true
		}
	}
	return false
}

// IsPackage reports whether dir holds a package with non-test Go files.
func (d Decls) IsPackage(dir string) bool {
	_, ok := d.Name[dir]
	return ok
}
