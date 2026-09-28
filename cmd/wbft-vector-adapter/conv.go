package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/types"
)

// Value conversions of the vector format (WBFT-VEC-014): integers are decimal
// strings, byte strings are 0x-prefixed lowercase hexadecimal, absent values
// are null.

var errInput = errors.New("malformed case input")

// decode unmarshals the case input into v, rejecting unknown fields so that a
// schema change is noticed.
func decode(input json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(input)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", errInput, err)
	}
	return nil
}

// Hex is a byte string in the vector format.
type Hex []byte

// UnmarshalJSON accepts "0x" followed by an even number of hex digits.
func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "0x") {
		return fmt.Errorf("%w: byte string %q without 0x", errInput, s)
	}
	v, err := hex.DecodeString(s[2:])
	if err != nil {
		return fmt.Errorf("%w: %v", errInput, err)
	}
	*h = v
	return nil
}

// Dec is a non-negative integer in the vector format.
type Dec struct{ big.Int }

// UnmarshalJSON accepts a decimal string.
func (d *Dec) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if _, ok := d.SetString(s, 10); !ok || d.Sign() < 0 || s == "" || (len(s) > 1 && s[0] == '0') {
		return fmt.Errorf("%w: integer %q", errInput, s)
	}
	return nil
}

// Uint64Checked returns d, failing when it does not fit in 64 bits.
func (d *Dec) Uint64Checked() (uint64, error) {
	if !d.IsUint64() {
		return 0, fmt.Errorf("%w: integer %s out of range", errInput, d.String())
	}
	return d.Uint64(), nil
}

// hexOut renders b in the vector format.
func hexOut(b []byte) string { return "0x" + hex.EncodeToString(b) }

// decOut renders an unsigned integer in the vector format.
func decOut(v uint64) string { return strconv.FormatUint(v, 10) }

// bigOut renders a big integer, or null for nil.
func bigOut(b *big.Int) any {
	if b == nil {
		return nil
	}
	return b.String()
}

func addrOut(a types.Address) string { return hexOut(a[:]) }

func hexList(bs [][]byte) []any {
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = hexOut(b)
	}
	return out
}

// toAddress converts a 20-byte string.
func toAddress(b Hex) (types.Address, error) {
	if len(b) != 20 {
		return types.Address{}, fmt.Errorf("%w: address of %d bytes", errInput, len(b))
	}
	return types.Address(b), nil
}

// toHash converts a 32-byte string.
func toHash(b Hex) (types.Hash, error) {
	if len(b) != 32 {
		return types.Hash{}, fmt.Errorf("%w: hash of %d bytes", errInput, len(b))
	}
	return types.Hash(b), nil
}

func toUint32(d Dec) (uint32, error) {
	v, err := d.Uint64Checked()
	if err != nil || v > 0xffffffff {
		return 0, fmt.Errorf("%w: %s does not fit in 32 bits", errInput, d.String())
	}
	return uint32(v), nil
}

// obj is a JSON object of a handler output.
type obj = map[string]any

// itoa64 renders a signed integer (only fields the schema declares signed).
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
