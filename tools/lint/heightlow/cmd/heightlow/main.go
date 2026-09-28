// Command heightlow runs the heightlow analyzer over the given packages and
// then checks that every site label named with -require has an annotated use.
//
// Usage (from the root of the wbft module):
//
//	go -C tools build -o ../bin/heightlow ./lint/heightlow/cmd/heightlow
//	bin/heightlow -require HH-20,HH-21 ./...
//
// It exits with status 1 when the analyzer reports a use or a required label
// has no use, and 2 on a usage or load error.
package main

import (
	"flag"
	"fmt"
	"go/token"
	"os"
	"slices"
	"strings"

	"github.com/0xmhha/wbft/tools/lint/heightlow"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

func main() {
	require := flag.String("require", "", "comma-separated site labels (HH-nn) that must have at least one annotated use")
	flag.Parse()
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heightlow:", err)
		os.Exit(2)
	}
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(2)
	}
	failed := false
	seen := map[string]bool{}
	for _, p := range pkgs {
		pass := &analysis.Pass{
			Analyzer:  heightlow.Analyzer,
			Fset:      p.Fset,
			Files:     p.Syntax,
			Pkg:       p.Types,
			TypesInfo: p.TypesInfo,
			Report: func(d analysis.Diagnostic) {
				failed = true
				fmt.Fprintf(os.Stderr, "%s: %s\n", position(p.Fset, d.Pos), d.Message)
			},
		}
		res, err := heightlow.Analyzer.Run(pass)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heightlow:", err)
			os.Exit(2)
		}
		for _, r := range res.(heightlow.Rows) {
			seen[r] = true
		}
	}
	var missing []string
	for _, r := range strings.Split(*require, ",") {
		if r = strings.TrimSpace(r); r != "" && !seen[r] {
			missing = append(missing, r)
		}
	}
	slices.Sort(missing)
	for _, r := range missing {
		failed = true
		fmt.Fprintf(os.Stderr, "heightlow: required label %s has no annotated use\n", r)
	}
	if failed {
		os.Exit(1)
	}
}

func position(fset *token.FileSet, pos token.Pos) string { return fset.Position(pos).String() }
