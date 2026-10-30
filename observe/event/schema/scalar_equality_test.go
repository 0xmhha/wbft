package schema

import (
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"testing"
)

type scalarString string
type scalarBoolean bool

func TestScalarEqualityPreservesDecodedValues(t *testing.T) {
	var pointer *string
	var object map[string]any
	var array []any
	values := []any{
		nil, "", "kind", "other", true, false,
		scalarString("kind"), scalarBoolean(true),
		json.Number("1"), json.Number("1.0"), json.Number("1e0"),
		json.Number("0"), json.Number("-0"), json.Number("18446744073709551616"),
		json.Number(""), json.Number("invalid"),
		pointer, object, array, []any{}, map[string]any{},
		[]any{json.Number("1")}, []any{json.Number("1.0")},
		map[string]any{"n": json.Number("1")}, map[string]any{"n": json.Number("1.0")},
		float64(1), float64(0), math.NaN(), math.Inf(1), 1, uint64(1),
	}
	for i, a := range values {
		for j, b := range values {
			got, want := equal(a, b), scalarEqualityReference(a, b)
			if got != want {
				t.Fatalf("values %d and %d (%T, %T): got %t, want %t", i, j, a, b, got, want)
			}
		}
	}
	t.Logf("scalar equality parity: %d pairs", len(values)*len(values))
}

func scalarEqualityReference(a, b any) bool {
	x, okx := a.(json.Number)
	y, oky := b.(json.Number)
	if okx && oky {
		rx, ok1 := new(big.Rat).SetString(x.String())
		ry, ok2 := new(big.Rat).SetString(y.String())
		return ok1 && ok2 && rx.Cmp(ry) == 0
	}
	return reflect.DeepEqual(a, b)
}
