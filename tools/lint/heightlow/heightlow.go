// Package heightlow is a go/analysis analyzer that keeps the truncation of
// block numbers, sequences and rounds to their low bits where the reference
// implementation truncates, and nowhere else.
//
// The accessors RefLow64 and RefLowInt64 of types.Height and RefLow64 and
// RefLow32 of types.Round reproduce big.Int.Uint64, Int64 and
// uint32(Uint64()) of the reference. Every use of one of them outside package
// types (test files excepted) must carry a directive
//
//	//wbft:low64 HH-nn [note]
//
// on its line or on the line above, where HH-nn is a row of the table of
// reference places in the wbft height-handling design (flag -rows). The
// command in cmd/heightlow also checks the other direction: every row given
// with -require has at least one annotated use.
package heightlow

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Directive marks a use of a truncating accessor.
const Directive = "//wbft:low64"

const (
	defaultModule = "github.com/0xmhha/wbft"
	// defaultRows are the rows of the table of reference places: consensus
	// core (HH-01 .. HH-14), header rules (HH-20 .. HH-34), validator sets
	// and epochs (HH-40 .. HH-48), execution (HH-50 .. HH-55), the
	// execution layer (HH-60 .. HH-67) and rounds (HH-70 .. HH-77).
	defaultRows = "01-14,20-34,40-48,50-55,60-67,70-77"
)

var (
	flagModule string
	flagRows   string
)

// Analyzer is the heightlow analyzer. Its result is the sorted list of rows
// named by the valid directives on uses in the package.
var Analyzer = &analysis.Analyzer{
	Name:       "heightlow",
	Doc:        "report uses of the truncating height and round accessors without a //wbft:low64 HH-nn directive",
	URL:        "https://github.com/0xmhha/wbft/tree/main/tools/lint/heightlow",
	Run:        run,
	ResultType: typeOfRows,
}

func init() {
	Analyzer.Flags.StringVar(&flagModule, "module", defaultModule, "module path of wbft")
	Analyzer.Flags.StringVar(&flagRows, "rows", defaultRows, "comma-separated row ranges of the table (numbers without the HH- prefix)")
}

// Rows is the result type: the rows named by annotated uses.
type Rows []string

var typeOfRows = typeOf[Rows]()

// accessors are the truncating methods, by receiver type name.
var accessors = map[string][]string{
	"Height": {"RefLow64", "RefLowInt64"},
	"Round":  {"RefLow64", "RefLow32"},
}

func run(pass *analysis.Pass) (any, error) {
	path := pass.Pkg.Path()
	if path != flagModule && !strings.HasPrefix(path, flagModule+"/") {
		return Rows(nil), nil
	}
	if path == flagModule+"/types" {
		return Rows(nil), nil // the accessors themselves
	}
	known := parseRows(flagRows)
	seen := map[string]bool{}
	for _, f := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(f.Pos()).Name(), "_test.go") {
			continue
		}
		dirs := directives(pass.Fset, f)
		code := codeLines(pass.Fset, f)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !isAccessor(pass.TypesInfo, sel, flagModule+"/types") {
				return true
			}
			line := pass.Fset.Position(sel.Sel.Pos()).Line
			row, ok := dirs[line]
			if !ok && !code[line-1] {
				// a directive on a line of its own applies to the next line
				row, ok = dirs[line-1]
			}
			switch {
			case !ok:
				pass.Reportf(sel.Sel.Pos(), "%s without %s HH-nn: truncate only where the reference truncates, and name the row", sel.Sel.Name, Directive)
			case !known[row]:
				pass.Reportf(sel.Sel.Pos(), "%s names unknown row %s", Directive, row)
			default:
				seen[row] = true
			}
			return true
		})
	}
	out := make(Rows, 0, len(seen))
	for r := range seen { //wbft:unordered sorted below
		out = append(out, r)
	}
	slices.Sort(out)
	return out, nil
}

// isAccessor reports whether sel selects a truncating accessor of
// types.Height or types.Round.
func isAccessor(info *types.Info, sel *ast.SelectorExpr, typesPkg string) bool {
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	rt := sig.Recv().Type()
	if p, ok := rt.(*types.Pointer); ok {
		rt = p.Elem()
	}
	named, ok := rt.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != typesPkg {
		return false
	}
	return slices.Contains(accessors[named.Obj().Name()], fn.Name())
}

var directiveRE = regexp.MustCompile(`^` + regexp.QuoteMeta(Directive) + `\s+(HH-\d{2})\b`)

// directives maps the lines of f that hold a directive to the row it names.
// A directive without a well-formed row is recorded with an empty row, which
// is reported as unknown.
func directives(fset *token.FileSet, f *ast.File) map[int]string {
	out := map[int]string{}
	for _, cg := range f.Comments {
		for _, cm := range cg.List {
			if !strings.HasPrefix(cm.Text, Directive) {
				continue
			}
			row := ""
			if m := directiveRE.FindStringSubmatch(cm.Text); m != nil {
				row = m[1]
			}
			out[fset.Position(cm.Slash).Line] = row
		}
	}
	return out
}

// codeLines returns the lines of f on which a declaration, statement or
// expression starts or ends.
func codeLines(fset *token.FileSet, f *ast.File) map[int]bool {
	out := map[int]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case nil, *ast.File, *ast.Comment, *ast.CommentGroup:
			return true
		}
		out[fset.Position(n.Pos()).Line] = true
		out[fset.Position(n.End()).Line] = true
		return true
	})
	return out
}

// parseRows expands "01-14,20" into the set {HH-01 .. HH-14, HH-20}.
func parseRows(spec string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, found := strings.Cut(part, "-")
		if !found {
			hi = lo
		}
		a, b := atoi(lo), atoi(hi)
		for i := a; i <= b && a >= 0; i++ {
			out["HH-"+pad2(i)] = true
		}
	}
	return out
}

func atoi(s string) int {
	n := 0
	if s == "" {
		return -1
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func pad2(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
