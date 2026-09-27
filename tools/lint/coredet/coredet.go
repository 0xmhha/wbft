// Package coredet is a go/analysis analyzer that keeps the consensus core and
// the pure modules of wbft deterministic, so that every run can be replayed
// exactly.
//
// It reports, in the packages it targets (non-test files only):
//
//   - go statements, select statements, channel types, channel sends and
//     receives, and range over a channel ("concurrency");
//   - range over a map, or over maps.Keys/maps.Values/maps.All, unless the
//     statement carries a "//wbft:unordered <reason>" comment on its line or
//     on the line above ("unordered iteration").
//
// Concurrency is forbidden in the core packages everywhere and in the pure
// packages everywhere except in the functions listed by -allow. Iterating in
// sorted key order (for example slices.Sorted(maps.Keys(m))) needs no
// comment.
//
// Import and call bans (clocks, randomness, unstable sorts, sync in the core)
// are enforced by depguard and forbidigo in .golangci.yml; this analyzer
// covers what those linters cannot see.
package coredet

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Directive marks a map iteration whose order does not affect any output.
const Directive = "//wbft:unordered"

// Defaults of the flags: the package groups of the determinism rules.
const (
	defaultModule = "github.com/0xmhha/wbft"
	defaultCore   = "consensus,consensus/inputlog"
	defaultPure   = "crypto/keccak,internal/refsort,types,codec/rlp,codec,crypto/ecdsa,crypto/bls,validator,epoch,header"
	defaultAllow  = "header.VerifyHeaders"
)

var (
	flagModule string
	flagCore   string
	flagPure   string
	flagAllow  string
)

// Analyzer is the coredet analyzer.
var Analyzer = &analysis.Analyzer{
	Name: "coredet",
	Doc:  "report concurrency and unannotated map iteration in the deterministic packages of wbft",
	URL:  "https://github.com/0xmhha/wbft/tree/main/tools/lint/coredet",
	Run:  run,
}

func init() {
	Analyzer.Flags.StringVar(&flagModule, "module", defaultModule, "module path that prefixes the package lists")
	Analyzer.Flags.StringVar(&flagCore, "core", defaultCore, "comma-separated core packages, relative to -module")
	Analyzer.Flags.StringVar(&flagPure, "pure", defaultPure, "comma-separated pure packages, relative to -module")
	Analyzer.Flags.StringVar(&flagAllow, "allow", defaultAllow, "comma-separated pkg.Func of pure packages where concurrency is allowed")
}

// group is the determinism group of a package.
type group int

const (
	groupNone group = iota
	groupCore
	groupPure
)

func classify(pkgPath string) (group, string) {
	rel, ok := strings.CutPrefix(pkgPath, flagModule+"/")
	if !ok {
		return groupNone, ""
	}
	if contains(flagCore, rel) {
		return groupCore, rel
	}
	if contains(flagPure, rel) {
		return groupPure, rel
	}
	return groupNone, rel
}

func contains(list, item string) bool {
	for _, s := range strings.Split(list, ",") {
		if strings.TrimSpace(s) == item {
			return true
		}
	}
	return false
}

func run(pass *analysis.Pass) (any, error) {
	grp, rel := classify(pass.Pkg.Path())
	if grp == groupNone {
		return nil, nil
	}
	for _, f := range pass.Files {
		name := pass.Fset.File(f.Pos()).Name()
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		c := &checker{pass: pass, directives: directiveLines(pass.Fset, f)}
		for _, decl := range f.Decls {
			allowed := false
			if fd, ok := decl.(*ast.FuncDecl); ok && grp == groupPure && fd.Recv == nil {
				allowed = contains(flagAllow, lastElem(rel)+"."+fd.Name.Name)
			}
			c.concurrency = !allowed
			ast.Inspect(decl, c.visit)
		}
	}
	return nil, nil
}

func lastElem(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

type checker struct {
	pass        *analysis.Pass
	directives  map[int]bool // lines carrying a valid Directive
	concurrency bool         // report concurrency constructs
}

func (c *checker) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.GoStmt:
		c.reportConcurrency(n.Pos(), "go statement")
	case *ast.SelectStmt:
		c.reportConcurrency(n.Pos(), "select statement")
	case *ast.ChanType:
		c.reportConcurrency(n.Pos(), "channel type")
	case *ast.SendStmt:
		c.reportConcurrency(n.Pos(), "channel send")
	case *ast.UnaryExpr:
		if n.Op == token.ARROW {
			c.reportConcurrency(n.Pos(), "channel receive")
		}
	case *ast.RangeStmt:
		c.checkRange(n)
	}
	return true
}

func (c *checker) reportConcurrency(pos token.Pos, what string) {
	if c.concurrency {
		c.pass.Reportf(pos, "%s in a deterministic package: the core is driven by inputs, not goroutines or channels", what)
	}
}

func (c *checker) checkRange(rs *ast.RangeStmt) {
	t := c.pass.TypesInfo.TypeOf(rs.X)
	if t == nil {
		return
	}
	switch t.Underlying().(type) {
	case *types.Chan:
		c.reportConcurrency(rs.Pos(), "range over a channel")
		return
	case *types.Map:
		c.checkUnordered(rs, "range over a map")
		return
	}
	if call, ok := ast.Unparen(rs.X).(*ast.CallExpr); ok && isMapsIterator(c.pass.TypesInfo, call) {
		c.checkUnordered(rs, "range over a map iterator")
	}
}

// isMapsIterator reports whether call is maps.Keys, maps.Values or maps.All.
func isMapsIterator(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "maps" {
		return false
	}
	switch fn.Name() {
	case "Keys", "Values", "All":
		return true
	}
	return false
}

func (c *checker) checkUnordered(rs *ast.RangeStmt, what string) {
	line := c.pass.Fset.Position(rs.Pos()).Line
	if c.directives[line] || c.directives[line-1] {
		return
	}
	c.pass.Reportf(rs.Pos(), "%s without %s <reason>: iterate in sorted order, or state why the order cannot reach any output", what, Directive)
}

// directiveRE matches the directive followed by a non-empty reason.
var directiveRE = regexp.MustCompile(`^` + regexp.QuoteMeta(Directive) + `\s+\S`)

// directiveLines returns the lines of f that hold a directive with a reason.
func directiveLines(fset *token.FileSet, f *ast.File) map[int]bool {
	lines := map[int]bool{}
	for _, cg := range f.Comments {
		for _, cm := range cg.List {
			if directiveRE.MatchString(cm.Text) {
				lines[fset.Position(cm.Slash).Line] = true
			}
		}
	}
	return lines
}
