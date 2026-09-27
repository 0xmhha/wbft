package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Row is one requirement of the traceability matrix.
type Row struct {
	ID       string
	Source   string   // specification file or list that declared the ID
	Owner    string   // from owners.yaml
	Symbols  string   // from owners.yaml
	Class    string   // from owners.yaml
	Code     []string // positions of "// Spec:" comments
	Tests    []string // positions of "// Covers:" comments
	Handlers []string // sorted "<runner>/<handler>" of vectors citing the ID
	Cases    int      // number of vector cases citing the ID
}

// Matrix is the traceability matrix and the inconsistencies found while
// building it.
type Matrix struct {
	Rows []Row
	// Unknown lists references to IDs that are not in the requirement list,
	// as "kind: ID (where)".
	Unknown []string
}

// Inputs are the sources of the matrix; all but Requirements are optional.
type Inputs struct {
	Requirements []Requirement
	Vectors      []VectorCase
	Owners       map[string]Owner
	OwnerOrder   []string
	Code         []CodeRef
	Keep         func(id string) bool // nil keeps every ID
}

// Build joins the inputs into a matrix, one row per kept requirement in the
// order of Inputs.Requirements.
func Build(in Inputs) Matrix {
	keep := in.Keep
	if keep == nil {
		keep = func(string) bool { return true }
	}
	var m Matrix
	index := map[string]int{}
	for _, r := range in.Requirements {
		if !keep(r.ID) {
			continue
		}
		index[r.ID] = len(m.Rows)
		m.Rows = append(m.Rows, Row{ID: r.ID, Source: r.Source})
	}
	for _, id := range in.OwnerOrder {
		if !keep(id) {
			continue
		}
		i, ok := index[id]
		if !ok {
			m.Unknown = append(m.Unknown, "owners: "+id)
			continue
		}
		o := in.Owners[id]
		m.Rows[i].Owner, m.Rows[i].Symbols, m.Rows[i].Class = o.Owner, o.Symbols, o.Class
	}
	for _, vc := range in.Vectors {
		for _, id := range vc.Requirements {
			if !keep(id) {
				continue
			}
			i, ok := index[id]
			if !ok {
				m.Unknown = append(m.Unknown, fmt.Sprintf("vector: %s (%s/%s)", id, vc.HandlerName(), vc.Case))
				continue
			}
			row := &m.Rows[i]
			row.Cases++
			if h := vc.HandlerName(); !slices.Contains(row.Handlers, h) {
				row.Handlers = append(row.Handlers, h)
			}
		}
	}
	for _, ref := range in.Code {
		if !keep(ref.ID) {
			continue
		}
		i, ok := index[ref.ID]
		if !ok {
			m.Unknown = append(m.Unknown, fmt.Sprintf("code: %s (%s)", ref.ID, ref.Pos))
			continue
		}
		if ref.Test {
			m.Rows[i].Tests = append(m.Rows[i].Tests, ref.Pos)
		} else {
			m.Rows[i].Code = append(m.Rows[i].Code, ref.Pos)
		}
	}
	for i := range m.Rows {
		slices.Sort(m.Rows[i].Handlers)
	}
	return m
}

var header = []string{"id", "source", "owner", "symbols", "class", "code", "tests", "vector_handlers", "vector_cases"}

func (r Row) fields() []string {
	return []string{
		r.ID, r.Source, r.Owner, r.Symbols, r.Class,
		strings.Join(r.Code, " "), strings.Join(r.Tests, " "),
		strings.Join(r.Handlers, " "), strconv.Itoa(r.Cases),
	}
}

// WriteCSV writes the matrix as CSV with a header line.
func (m Matrix) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, r := range m.Rows {
		if err := cw.Write(r.fields()); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteMarkdown writes the matrix as a Markdown table.
func (m Matrix) WriteMarkdown(w io.Writer) error {
	esc := strings.NewReplacer("|", `\|`, "\n", " ")
	line := func(cells []string) error {
		for i, c := range cells {
			cells[i] = esc.Replace(c)
		}
		_, err := fmt.Fprintf(w, "| %s |\n", strings.Join(cells, " | "))
		return err
	}
	if err := line(slices.Clone(header)); err != nil {
		return err
	}
	sep := make([]string, len(header))
	for i := range sep {
		sep[i] = "---"
	}
	if err := line(sep); err != nil {
		return err
	}
	for _, r := range m.Rows {
		if err := line(r.fields()); err != nil {
			return err
		}
	}
	return nil
}

// Summary returns counts for a one-line report.
func (m Matrix) Summary() string {
	withVectors, withOwner, withCode := 0, 0, 0
	for _, r := range m.Rows {
		if len(r.Handlers) > 0 {
			withVectors++
		}
		if r.Owner != "" {
			withOwner++
		}
		if len(r.Code) > 0 {
			withCode++
		}
	}
	return fmt.Sprintf("requirements=%d with_owner=%d with_vectors=%d with_code=%d unknown_refs=%d",
		len(m.Rows), withOwner, withVectors, withCode, len(m.Unknown))
}
