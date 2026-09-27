package main

// The two YAML readers below accept only the small subsets that meta.yaml
// and owners.yaml use, so that the tool needs no YAML dependency. Anything
// outside the subset is an error rather than a silent misread.

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// unquote returns a scalar without surrounding quotes and trailing comment.
func unquote(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, `"`):
		s, err := strconv.Unquote(v)
		if err != nil {
			return "", fmt.Errorf("bad double-quoted scalar %s", v)
		}
		return s, nil
	case strings.HasPrefix(v, `'`):
		if len(v) < 2 || !strings.HasSuffix(v, `'`) {
			return "", fmt.Errorf("bad single-quoted scalar %s", v)
		}
		return strings.ReplaceAll(v[1:len(v)-1], `''`, `'`), nil
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v, nil
}

// parseMeta reads the fields of a vector meta.yaml that the matrix needs:
// runner, handler, case and the requirements list. Nested mappings (for
// example reference and generator) are skipped.
func parseMeta(data []byte) (VectorCase, error) {
	var vc VectorCase
	inReqs := false
	for n, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indented := line[0] == ' '
		if indented {
			if inReqs && strings.HasPrefix(trimmed, "- ") {
				id, err := unquote(trimmed[2:])
				if err != nil {
					return vc, fmt.Errorf("line %d: %w", n+1, err)
				}
				vc.Requirements = append(vc.Requirements, id)
			}
			continue // nested mapping content
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return vc, fmt.Errorf("line %d: expected key: value", n+1)
		}
		inReqs = false
		val = strings.TrimSpace(val)
		switch key {
		case "runner", "handler", "case":
			s, err := unquote(val)
			if err != nil {
				return vc, fmt.Errorf("line %d: %w", n+1, err)
			}
			switch key {
			case "runner":
				vc.Runner = s
			case "handler":
				vc.Handler = s
			case "case":
				vc.Case = s
			}
		case "requirements":
			switch {
			case val == "":
				inReqs = true
			case strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]"):
				for _, item := range strings.Split(val[1:len(val)-1], ",") {
					if strings.TrimSpace(item) == "" {
						continue
					}
					id, err := unquote(item)
					if err != nil {
						return vc, fmt.Errorf("line %d: %w", n+1, err)
					}
					vc.Requirements = append(vc.Requirements, id)
				}
			default:
				return vc, fmt.Errorf("line %d: requirements must be a list", n+1)
			}
		}
	}
	if vc.Runner == "" || vc.Handler == "" {
		return vc, fmt.Errorf("runner or handler missing")
	}
	return vc, nil
}

var (
	ownerKeyRE   = regexp.MustCompile(`^((?:WBFT|SNET)-[A-Z]+-[0-9]{3}):\s*$`)
	ownerFieldRE = regexp.MustCompile(`^  ([a-z]+):\s*(.*)$`)
)

// ParseOwners reads owners.yaml: a mapping from requirement ID to a mapping
// with the scalar fields owner, symbols, class and reason.
//
//	WBFT-SM-041:
//	  owner: consensus
//	  symbols: consensus.CheckMessage
func ParseOwners(r io.Reader) (map[string]Owner, []string, error) {
	owners := map[string]Owner{}
	var order []string
	cur := ""
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), " \r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := ownerKeyRE.FindStringSubmatch(line); m != nil {
			cur = m[1]
			if _, dup := owners[cur]; dup {
				return nil, nil, fmt.Errorf("line %d: %s listed twice", n, cur)
			}
			owners[cur] = Owner{}
			order = append(order, cur)
			continue
		}
		m := ownerFieldRE.FindStringSubmatch(line)
		if m == nil || cur == "" {
			return nil, nil, fmt.Errorf("line %d: expected \"ID:\" or \"  field: value\"", n)
		}
		val, err := unquote(m[2])
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", n, err)
		}
		o := owners[cur]
		switch m[1] {
		case "owner":
			o.Owner = val
		case "symbols":
			o.Symbols = val
		case "class":
			switch val {
			case "external", "deployment", "spec", "withdrawn":
			default:
				return nil, nil, fmt.Errorf("line %d: unknown class %q", n, val)
			}
			o.Class = val
		case "reason":
			o.Reason = val
		default:
			return nil, nil, fmt.Errorf("line %d: unknown field %q", n, m[1])
		}
		owners[cur] = o
	}
	return owners, order, sc.Err()
}
