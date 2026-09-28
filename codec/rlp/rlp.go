package rlp

import (
	"errors"

	gethrlp "github.com/ethereum/go-ethereum/rlp"
)

// RawValue is an encoded RLP item that has not been decoded.
type RawValue = gethrlp.RawValue

// EmptyString and EmptyList are the encodings of an empty byte string (0x80)
// and an empty list (0xc0): the "absent" values of A-03 section 2.4.
var (
	EmptyString = []byte{0x80}
	EmptyList   = []byte{0xc0}
)

// ErrDecode wraps every decoding failure of this package and of codec.
type ErrDecode struct{ Err error }

func (e *ErrDecode) Error() string { return "rlp decode: " + e.Err.Error() }
func (e *ErrDecode) Unwrap() error { return e.Err }

func wrap(err error) error {
	if err == nil {
		return nil
	}
	var d *ErrDecode
	if errors.As(err, &d) {
		return err
	}
	return &ErrDecode{Err: err}
}

// DecodeStrict decodes b as exactly one RLP value into v. It rejects
// non-canonical encodings (single bytes below 0x80 written as strings,
// long-form lengths below 56, leading zero bytes in lengths and integers) and
// bytes after the value.
//
// Spec: WBFT-ENC-001, WBFT-ENC-002, WBFT-ENC-003, WBFT-ENC-004, WBFT-ENC-005, WBFT-ENC-010, WBFT-ENC-011
func DecodeStrict(b []byte, v any) error {
	return wrap(gethrlp.DecodeBytes(b, v))
}

// Encode returns the RLP encoding of v.
func Encode(v any) ([]byte, error) {
	return gethrlp.EncodeToBytes(v)
}

// SplitList returns the content of the list b encodes and the bytes after it.
func SplitList(b []byte) (content, rest []byte, err error) {
	content, rest, err = gethrlp.SplitList(b)
	return content, rest, wrap(err)
}

// Items returns the encoded items of the list content, in order. It fails on
// an item that is not canonical or runs past the end.
func Items(content []byte) ([]RawValue, error) {
	var out []RawValue
	for len(content) > 0 {
		_, _, rest, err := gethrlp.Split(content)
		if err != nil {
			return nil, wrap(err)
		}
		out = append(out, RawValue(content[:len(content)-len(rest)]))
		content = rest
	}
	return out, nil
}

// ListItems decodes b as exactly one list and returns its encoded items.
//
// Spec: WBFT-ENC-003
func ListItems(b []byte) ([]RawValue, error) {
	content, rest, err := SplitList(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, wrap(gethrlp.ErrMoreThanOneValue)
	}
	return Items(content)
}

// EncodeString returns the RLP string encoding of b.
func EncodeString(b []byte) []byte {
	out, _ := gethrlp.EncodeToBytes(b) // encoding a byte slice cannot fail
	return out
}

// EncodeList returns the RLP list whose items are the given encoded items.
func EncodeList(items ...[]byte) []byte {
	raws := make([]RawValue, len(items))
	for i, it := range items {
		raws[i] = it
	}
	out, _ := gethrlp.EncodeToBytes(raws) // raw values are copied verbatim
	return out
}

// Stream re-exports the RLP stream decoder for codecs that read items one by
// one.
type Stream = gethrlp.Stream

// Kind re-exports the item kinds of a Stream.
type Kind = gethrlp.Kind

// Item kinds.
const (
	Byte   = gethrlp.Byte
	String = gethrlp.String
	List   = gethrlp.List
)

// SplitString returns the content of the RLP byte string at the start of b
// and the bytes after it. A single byte below 0x80 is its own content. It
// fails when b starts with a list, with a non-canonical size, or with a size
// that runs past the end of b.
func SplitString(b []byte) (content, rest []byte, err error) {
	content, rest, err = gethrlp.SplitString(b)
	return content, rest, wrap(err)
}
