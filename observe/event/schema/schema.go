// Package schema holds the schema of the event records, events-v1.json,
// and checks records against it (observe.md 2.1). The file is the source of
// the event vocabulary for the tools that do not import Go: a front end
// generates its types from it, the inspector its event model.
//
// The file is JSON Schema 2020-12. The checker implements only the keywords
// the file uses ($ref to "#/$defs/...", type, const, enum, pattern,
// minimum, maximum, minItems, maxItems, properties, required, additionalProperties,
// unevaluatedProperties, items, allOf, oneOf) and refuses a file that uses
// any other, so that the file cannot rely on a rule nobody checks.
package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

//go:embed events-v1.json
var eventsV1 []byte

// File returns the bytes of events-v1.json.
func File() []byte { return bytes.Clone(eventsV1) }

// ErrSchema reports a schema file the checker cannot use.
var ErrSchema = errors.New("schema: unsupported schema")

// Schema is a compiled schema.
type Schema struct {
	root *node
}

type node struct {
	ref                string
	target             *node
	types              []string
	constant           any
	hasConst           bool
	enum               []any
	pattern            *regexp.Regexp
	minimum            *big.Rat
	maximum            *big.Rat
	minItems, maxItems *big.Int
	props              map[string]*node
	order              []string // props with const or enum first: they reject other branches early
	required           []string
	additional         *node
	closed             bool // additionalProperties: false
	sealed             bool // unevaluatedProperties: false
	items              *node
	allOf              []*node
	oneOf              []*node
}

var annotations = map[string]bool{"$schema": true, "$id": true, "title": true, "description": true, "$comment": true, "$defs": true}

// Load compiles events-v1.json.
func Load() (*Schema, error) { return Compile(eventsV1) }

// Compile compiles a schema file.
func Compile(b []byte) (*Schema, error) {
	var doc map[string]any
	if err := decode(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	c := &compiler{defs: map[string]*node{}}
	raw, _ := doc["$defs"].(map[string]any)
	for name := range raw { //wbft:unordered each definition is compiled once, by name
		c.defs[name] = &node{}
	}
	for name, d := range raw { //wbft:unordered each definition is compiled once, by name
		if err := c.fill(c.defs[name], d, "#/$defs/"+name); err != nil {
			return nil, err
		}
	}
	root := &node{}
	if err := c.fill(root, doc, "#"); err != nil {
		return nil, err
	}
	return &Schema{root: root}, nil
}

type compiler struct {
	defs map[string]*node
}

func (c *compiler) fill(n *node, v any, at string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: %s is not an object", ErrSchema, at)
	}
	sub := func(k string, v any) (*node, error) {
		s := &node{}
		return s, c.fill(s, v, at+"/"+k)
	}
	list := func(k string, v any) ([]*node, error) {
		a, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: %s/%s is not an array", ErrSchema, at, k)
		}
		out := make([]*node, len(a))
		for i, x := range a {
			s, err := sub(fmt.Sprintf("%s/%d", k, i), x)
			if err != nil {
				return nil, err
			}
			out[i] = s
		}
		return out, nil
	}
	keys := make([]string, 0, len(m))
	for k := range m { //wbft:unordered sorted below
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var err error
	for _, k := range keys {
		x := m[k]
		switch k {
		case "$ref":
			s, _ := x.(string)
			name, ok := strings.CutPrefix(s, "#/$defs/")
			if !ok || c.defs[name] == nil {
				return fmt.Errorf("%w: %s: $ref %q", ErrSchema, at, s)
			}
			n.ref, n.target = s, c.defs[name]
		case "type":
			switch t := x.(type) {
			case string:
				n.types = []string{t}
			case []any:
				for _, e := range t {
					s, _ := e.(string)
					n.types = append(n.types, s)
				}
			}
			for _, t := range n.types {
				if !slices.Contains([]string{"object", "array", "string", "integer", "number", "boolean", "null"}, t) {
					return fmt.Errorf("%w: %s: type %q", ErrSchema, at, t)
				}
			}
		case "const":
			n.constant, n.hasConst = x, true
		case "enum":
			a, ok := x.([]any)
			if !ok {
				return fmt.Errorf("%w: %s: enum is not an array", ErrSchema, at)
			}
			n.enum = a
		case "pattern":
			s, _ := x.(string)
			if n.pattern, err = regexp.Compile(s); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrSchema, at, err)
			}
		case "minimum", "maximum":
			num, _ := x.(json.Number)
			r, ok := new(big.Rat).SetString(num.String())
			if !ok {
				return fmt.Errorf("%w: %s: %s %v", ErrSchema, at, k, x)
			}
			if k == "minimum" {
				n.minimum = r
			} else {
				n.maximum = r
			}
		case "minItems", "maxItems":
			num, _ := x.(json.Number)
			r, ok := new(big.Rat).SetString(num.String())
			if !ok || !r.IsInt() || r.Sign() < 0 {
				return fmt.Errorf("%w: %s: %s must be a non-negative integer", ErrSchema, at, k)
			}
			count := new(big.Int).Set(r.Num())
			if k == "minItems" {
				n.minItems = count
			} else {
				n.maxItems = count
			}
		case "properties":
			p, ok := x.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: %s: properties is not an object", ErrSchema, at)
			}
			n.props = map[string]*node{}
			for name, d := range p { //wbft:unordered the names are ordered below
				if n.props[name], err = sub("properties/"+name, d); err != nil {
					return err
				}
				n.order = append(n.order, name)
			}
			slices.Sort(n.order)
			slices.SortStableFunc(n.order, func(a, b string) int { return discriminates(n.props[b]) - discriminates(n.props[a]) })
		case "required":
			a, _ := x.([]any)
			for _, e := range a {
				s, _ := e.(string)
				n.required = append(n.required, s)
			}
		case "additionalProperties":
			if b, ok := x.(bool); ok {
				n.closed = !b
			} else if n.additional, err = sub(k, x); err != nil {
				return err
			}
		case "unevaluatedProperties":
			if b, ok := x.(bool); !ok || b {
				return fmt.Errorf("%w: %s: only unevaluatedProperties: false is supported", ErrSchema, at)
			}
			n.sealed = true
		case "items":
			if n.items, err = sub(k, x); err != nil {
				return err
			}
		case "allOf":
			if n.allOf, err = list(k, x); err != nil {
				return err
			}
		case "oneOf":
			if n.oneOf, err = list(k, x); err != nil {
				return err
			}
		default:
			if !annotations[k] {
				return fmt.Errorf("%w: %s: keyword %s", ErrSchema, at, k)
			}
		}
	}
	return nil
}

func discriminates(n *node) int {
	if n.hasConst || n.enum != nil {
		return 1
	}
	return 0
}

// Validate checks one record: a JSON object, optionally followed by a
// newline.
func (s *Schema) Validate(line []byte) error {
	var v any
	if err := decode(line, &v); err != nil {
		return err
	}
	_, err := validate(s.root, v, "")
	return err
}

// Kinds returns the event kinds the schema defines: the kind constants of
// the records the root lists, in its order.
func (s *Schema) Kinds() []string {
	var out []string
	for _, b := range s.root.oneOf {
		b = deref(b)
		if k := b.props["kind"]; k != nil && k.hasConst {
			if name, ok := k.constant.(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("schema: more than one JSON value")
	}
	return nil
}

func deref(n *node) *node {
	for n.target != nil && n.types == nil && n.props == nil && n.oneOf == nil && n.allOf == nil {
		n = n.target
	}
	return n
}

// validate checks v against n and returns the names of the properties of v
// that n evaluated (for unevaluatedProperties).
func validate(n *node, v any, at string) (map[string]bool, error) {
	fail := func(format string, args ...any) (map[string]bool, error) {
		where := at
		if where == "" {
			where = "/"
		}
		return nil, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...))
	}
	seen := map[string]bool{}
	if n.types != nil && !slices.ContainsFunc(n.types, func(t string) bool { return isType(v, t) }) {
		return fail("is %s, not %s", typeOf(v), strings.Join(n.types, " or "))
	}
	if n.hasConst && !equal(v, n.constant) {
		return fail("is %s, not %s", show(v), show(n.constant))
	}
	if n.enum != nil && !slices.ContainsFunc(n.enum, func(e any) bool { return equal(v, e) }) {
		return fail("%s is not one of %s", show(v), show(n.enum))
	}
	if n.pattern != nil {
		if s, ok := v.(string); ok && !n.pattern.MatchString(s) {
			return fail("%q does not match %s", s, n.pattern)
		}
	}
	if n.minimum != nil {
		if num, ok := v.(json.Number); ok {
			if r, ok := new(big.Rat).SetString(num.String()); ok && r.Cmp(n.minimum) < 0 {
				return fail("%s is below %s", num, n.minimum.RatString())
			}
		}
	}
	if n.maximum != nil {
		if num, ok := v.(json.Number); ok {
			if r, ok := new(big.Rat).SetString(num.String()); ok && r.Cmp(n.maximum) > 0 {
				return fail("%s is above %s", num, n.maximum.RatString())
			}
		}
	}
	if a, ok := v.([]any); ok {
		count := big.NewInt(int64(len(a)))
		if n.minItems != nil && count.Cmp(n.minItems) < 0 {
			return fail("has fewer than %s items", n.minItems.String())
		}
		if n.maxItems != nil && count.Cmp(n.maxItems) > 0 {
			return fail("has more than %s items", n.maxItems.String())
		}
		if n.items != nil {
			for i, e := range a {
				if _, err := validate(n.items, e, fmt.Sprintf("%s/%d", at, i)); err != nil {
					return nil, err
				}
			}
		}
	}
	obj, isObj := v.(map[string]any)
	if isObj {
		for _, k := range n.order {
			if e, ok := obj[k]; ok {
				if _, err := validate(n.props[k], e, at+"/"+k); err != nil {
					return nil, err
				}
				seen[k] = true
			}
		}
		for _, k := range n.required {
			if _, ok := obj[k]; !ok {
				return fail("lacks %s", k)
			}
		}
		if n.closed || n.additional != nil {
			for _, k := range sortedKeys(obj) {
				if n.props[k] != nil {
					continue
				}
				if n.closed {
					return fail("has %s", k)
				}
				if _, err := validate(n.additional, obj[k], at+"/"+k); err != nil {
					return nil, err
				}
				seen[k] = true
			}
		}
	}
	merge := func(m map[string]bool) {
		for k := range m { //wbft:unordered set union
			seen[k] = true
		}
	}
	if n.target != nil {
		m, err := validate(n.target, v, at)
		if err != nil {
			return nil, err
		}
		merge(m)
	}
	for _, s := range n.allOf {
		m, err := validate(s, v, at)
		if err != nil {
			return nil, err
		}
		merge(m)
	}
	if n.oneOf != nil {
		var match map[string]bool
		matches := 0
		var errs []error
		for _, s := range n.oneOf {
			if isObj && !mayMatch(s, obj) {
				continue
			}
			m, err := validate(s, v, at)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			matches++
			match = m
		}
		switch {
		case matches == 0 && len(errs) == 1:
			return nil, errs[0]
		case matches == 0:
			return fail("matches none of the %d alternatives", len(n.oneOf))
		case matches > 1:
			return fail("matches %d of the alternatives, not one", matches)
		}
		merge(match)
	}
	if isObj && n.sealed {
		for _, k := range sortedKeys(obj) {
			if !seen[k] {
				return fail("has %s", k)
			}
		}
	}
	return seen, nil
}

// mayMatch is false for an alternative that a property constant of obj
// rules out: a quick test that also tells which alternative a failing
// record meant.
func mayMatch(n *node, obj map[string]any) bool {
	n = deref(n)
	for k, p := range n.props { //wbft:unordered any mismatch rules it out
		if !p.hasConst {
			continue
		}
		e, ok := obj[k]
		if ok && !equal(e, p.constant) || !ok && requires(n, k) {
			return false
		}
	}
	return true
}

// requires reports whether n or one of its allOf schemas requires k.
func requires(n *node, k string) bool {
	n = deref(n)
	if slices.Contains(n.required, k) {
		return true
	}
	return slices.ContainsFunc(n.allOf, func(s *node) bool { return requires(s, k) })
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m { //wbft:unordered sorted below
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func isType(v any, t string) bool {
	switch t {
	case "integer":
		n, ok := v.(json.Number)
		return ok && !strings.ContainsAny(n.String(), ".eE")
	case "number":
		_, ok := v.(json.Number)
		return ok
	}
	return typeOf(v) == t
}

func typeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// equal compares decoded values; numbers compare by value.
func equal(a, b any) bool {
	x, okx := a.(json.Number)
	y, oky := b.(json.Number)
	if okx && oky {
		rx, ok1 := new(big.Rat).SetString(x.String())
		ry, ok2 := new(big.Rat).SetString(y.String())
		return ok1 && ok2 && rx.Cmp(ry) == 0
	}
	return reflect.DeepEqual(a, b)
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
