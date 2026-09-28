package stepdriver

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/0xmhha/wbft/transport"
)

// transportFrame is transport.DecodeFrame as a FrameDecoder.
func transportFrame(code uint64, payload []byte) ([]byte, uint64, FrameAction, string) {
	return transport.DecodeFrame(code, payload)
}

// yamlSubsetToJSON converts a vector file to JSON. Vector files use a YAML
// subset that maps one to one to JSON: block mappings and sequences indented
// by two spaces, double-quoted strings, true, false, null, [] and {}.
func yamlSubsetToJSON(path string) (json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []yline
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		ind := len(l) - len(strings.TrimLeft(l, " "))
		lines = append(lines, yline{ind, l[ind:]})
	}
	p := &yparser{lines: lines}
	v, err := p.value(0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.i != len(lines) {
		return nil, fmt.Errorf("%s: trailing content at line %d", path, p.i)
	}
	return json.Marshal(v)
}

type yline struct {
	indent int
	text   string
}

type yparser struct {
	lines []yline
	i     int
}

func scalar(s string) (any, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("scalar %q: %w", s, err)
	}
	return v, nil
}

// value parses the block starting at the current line, whose indentation is
// indent.
func (p *yparser) value(indent int) (any, error) {
	if p.i >= len(p.lines) {
		return nil, fmt.Errorf("unexpected end")
	}
	if strings.HasPrefix(p.lines[p.i].text, "- ") {
		return p.sequence(indent)
	}
	return p.mapping(indent)
}

func (p *yparser) sequence(indent int) (any, error) {
	out := []any{}
	for p.i < len(p.lines) && p.lines[p.i].indent == indent && strings.HasPrefix(p.lines[p.i].text, "- ") {
		rest := p.lines[p.i].text[2:]
		if k, _, ok := strings.Cut(rest, ":"); ok && !strings.HasPrefix(rest, "\"") && !strings.ContainsAny(k, " \"") {
			// A mapping whose first key is on the item line.
			p.lines[p.i] = yline{indent + 2, rest}
			m, err := p.mapping(indent + 2)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			continue
		}
		v, err := scalar(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.i++
	}
	return out, nil
}

func (p *yparser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for p.i < len(p.lines) && p.lines[p.i].indent == indent && !strings.HasPrefix(p.lines[p.i].text, "- ") {
		k, v, ok := strings.Cut(p.lines[p.i].text, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: no key", p.i)
		}
		p.i++
		v = strings.TrimSpace(v)
		if v != "" {
			s, err := scalar(v)
			if err != nil {
				return nil, err
			}
			out[k] = s
			continue
		}
		if p.i >= len(p.lines) || p.lines[p.i].indent <= indent {
			return nil, fmt.Errorf("line %d: key %s without value", p.i, k)
		}
		child, err := p.value(p.lines[p.i].indent)
		if err != nil {
			return nil, err
		}
		out[k] = child
	}
	return out, nil
}
