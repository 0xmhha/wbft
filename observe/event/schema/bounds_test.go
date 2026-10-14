package schema

import (
	"errors"
	"testing"
)

func TestExactNumericMaximumAndArrayBounds(t *testing.T) {
	for _, tc := range []struct {
		schema string
		values map[string]bool
	}{
		{`{"type":"number","maximum":18446744073709551616}`, map[string]bool{"18446744073709551616": true, "18446744073709551616.0": true, "18446744073709551617": false, "18446744073709551615": true}},
		{`{"type":"array","minItems":1e0,"maxItems":2.0,"items":{"minimum":0,"maximum":4}}`, map[string]bool{"[]": false, "[0]": true, "[4,1]": true, "[0,4,3]": false, "[5]": false}},
		{`{"maxItems":0}`, map[string]bool{"[]": true, "[1]": false, "\"unrelated\"": true}},
		{`{"minItems":18446744073709551616}`, map[string]bool{"[]": false, "[1]": false}},
	} {
		s, err := Compile([]byte(tc.schema))
		if err != nil {
			t.Fatal(err)
		}
		for value, want := range tc.values {
			if err := s.Validate([]byte(value)); (err == nil) != want {
				t.Fatal(tc.schema, value, err, want)
			}
		}
	}
	for _, raw := range []string{`{"maximum":null}`, `{"maximum":"4"}`, `{"minItems":-1}`, `{"maxItems":0.5}`, `{"maxItems":false}`, `{"minItems":"1"}`} {
		if _, err := Compile([]byte(raw)); !errors.Is(err, ErrSchema) {
			t.Fatal(raw, err)
		}
	}
}
