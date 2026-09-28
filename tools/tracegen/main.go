// Command tracegen builds the requirement traceability matrix of wbft.
//
// It joins four sources:
//
//   - the requirement list: the chapters of a specification directory
//     (-spec, text conversion of the "[ID]" lines) or a text file with IDs,
//     such as speclint output (-requirements);
//   - the conformance vectors: <runner>/<handler>/<case>/meta.yaml (-vectors);
//   - the owner table owners.yaml: requirement ID to package and symbols
//     (-owners; the table of this repository is internal/trace/owners.yaml);
//   - "// Spec: ID" comments in code and "// Covers: ID" comments in tests
//     (-code).
//
// Usage (from the root of the wbft module):
//
//	go -C tools run ./tracegen -spec ../wbft-spec/spec -vectors ../wbft-spec/vectors \
//	    -owners internal/trace/owners.yaml -code . -prefix WBFT- -format md
//
// Relative paths are resolved against the directory tracegen is started in.
// The matrix goes to standard output (or -o), a summary and every reference
// to an unknown ID go to standard error. With -strict, unknown references
// make the exit status 1.
//
// -write-baseline FILE records the requirement list and the vector-handler
// column of the matrix; -baseline FILE compares the matrix with such a file,
// prints every difference to standard error and makes the exit status 1 when
// there is one (the repository baseline is internal/trace/baseline.tsv).
//
// -check CHAPTERS (comma-separated, e.g. A-01,A-02) checks every wbft-owned
// requirement of those chapters for an owner package that exists, symbols,
// a "// Spec:" comment in an owner package and evidence: a vector handler
// that the adapter implements (-adapter runs the adapter and reads its hello;
// -handlers reads the names from a file) or a test with "// Covers: ID". It
// prints every gap to standard error and makes the exit status 1 when there
// is one. It needs -owners and -code.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tracegen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spec := fs.String("spec", "", "specification directory with the chapters (X-NN-*.md)")
	reqFile := fs.String("requirements", "", "text file with requirement IDs (e.g. speclint output); alternative to -spec")
	vectors := fs.String("vectors", "", "vector directory (<runner>/<handler>/<case>/meta.yaml)")
	owners := fs.String("owners", "", "owners.yaml")
	code := fs.String("code", "", "root of Go code to scan for // Spec: and // Covers: comments")
	prefix := fs.String("prefix", "", "keep only IDs with this prefix (e.g. WBFT-)")
	exclude := fs.String("exclude", "", "text file with IDs to leave out of the matrix")
	format := fs.String("format", "csv", "output format: csv or md")
	out := fs.String("o", "", "output file (default standard output)")
	strict := fs.Bool("strict", false, "exit 1 when a source references an ID that is not in the requirement list")
	baseline := fs.String("baseline", "", "baseline file to compare with; exit 1 when the requirement list or the vector handlers differ")
	writeBaseline := fs.String("write-baseline", "", "write the requirement list and vector handlers of the matrix to this baseline file")
	check := fs.String("check", "", "comma-separated chapters (e.g. A-01,A-08) whose wbft-owned requirements must have symbols, code and evidence")
	adapter := fs.String("adapter", "", "vector adapter binary whose hello lists the implemented handlers (with -check)")
	handlersFile := fs.String("handlers", "", "file with the implemented vector handlers (with -check; alternative to -adapter)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "tracegen: %v\n", err)
		return 2
	}
	if (*spec == "") == (*reqFile == "") {
		return fail(fmt.Errorf("give exactly one of -spec and -requirements"))
	}
	if *format != "csv" && *format != "md" {
		return fail(fmt.Errorf("unknown -format %q", *format))
	}
	if *baseline != "" && *writeBaseline != "" {
		return fail(fmt.Errorf("give at most one of -baseline and -write-baseline"))
	}
	if *check != "" && (*owners == "" || *code == "" || (*adapter == "") == (*handlersFile == "")) {
		return fail(fmt.Errorf("-check needs -owners, -code and exactly one of -adapter and -handlers"))
	}

	var in Inputs
	var err error
	if *spec != "" {
		in.Requirements, err = RequirementsFromSpec(*spec)
	} else {
		in.Requirements, err = readList(*reqFile)
	}
	if err != nil {
		return fail(err)
	}
	if len(in.Requirements) == 0 {
		return fail(fmt.Errorf("no requirement IDs found"))
	}
	if *vectors != "" {
		if in.Vectors, err = LoadVectors(*vectors); err != nil {
			return fail(err)
		}
	}
	if *owners != "" {
		f, err := os.Open(*owners)
		if err != nil {
			return fail(err)
		}
		in.Owners, in.OwnerOrder, err = ParseOwners(f)
		f.Close()
		if err != nil {
			return fail(fmt.Errorf("%s: %w", *owners, err))
		}
	}
	if *code != "" {
		if in.Code, err = ScanCode(*code); err != nil {
			return fail(err)
		}
	}
	excluded := map[string]bool{}
	if *exclude != "" {
		ids, err := readList(*exclude)
		if err != nil {
			return fail(err)
		}
		for _, r := range ids {
			excluded[r.ID] = true
		}
	}
	in.Keep = func(id string) bool { return strings.HasPrefix(id, *prefix) && !excluded[id] }

	m := Build(in)

	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)
	if *format == "md" {
		err = m.WriteMarkdown(bw)
	} else {
		err = m.WriteCSV(bw)
	}
	if err == nil {
		err = bw.Flush()
	}
	if err != nil {
		return fail(err)
	}
	for _, u := range m.Unknown {
		fmt.Fprintf(stderr, "tracegen: unknown ID in %s\n", u)
	}
	fmt.Fprintf(stderr, "tracegen: %s cases=%d\n", m.Summary(), len(in.Vectors))
	status := 0
	if *strict && len(m.Unknown) > 0 {
		status = 1
	}
	if *writeBaseline != "" {
		if err := writeBaselineFile(*writeBaseline, m.Baseline()); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stderr, "tracegen: wrote baseline %s (%d requirements)\n", *writeBaseline, len(m.Rows))
	}
	if *baseline != "" {
		want, err := readBaselineFile(*baseline)
		if err != nil {
			return fail(err)
		}
		if diff := CompareBaseline(want, m.Baseline()); len(diff) > 0 {
			fmt.Fprintf(stderr, "tracegen: matrix differs from baseline %s:\n", *baseline)
			for _, d := range diff {
				fmt.Fprintf(stderr, "  %s\n", d)
			}
			fmt.Fprintf(stderr, "tracegen: %d differences; if the change is intended, regenerate the baseline with -write-baseline and review the diff\n", len(diff))
			status = 1
		} else {
			fmt.Fprintf(stderr, "tracegen: matrix matches baseline %s (%d requirements)\n", *baseline, len(want))
		}
	}
	if *check != "" {
		var handlers map[string]bool
		if *adapter != "" {
			handlers, err = AdapterHandlers(*adapter)
		} else {
			handlers, err = readHandlers(*handlersFile)
		}
		if err != nil {
			return fail(err)
		}
		decls, err := ScanDecls(*code)
		if err != nil {
			return fail(err)
		}
		res := Check(m, splitList(*check), handlers, decls)
		for _, g := range res.Gaps {
			fmt.Fprintf(stderr, "tracegen: gap %s\n", g)
		}
		fmt.Fprintf(stderr, "tracegen: check %s: %s\n", *check, res.Summary())
		if !res.Complete() {
			status = 1
		}
	}
	return status
}

func writeBaselineFile(path string, entries []BaselineEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	err = WriteBaseline(bw, entries)
	if err == nil {
		err = bw.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func readBaselineFile(path string) ([]BaselineEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadBaseline(f, path)
}

func readList(path string) ([]Requirement, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return RequirementsFromList(f, path)
}
