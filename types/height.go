package types

import (
	"errors"
	"math/big"
)

// ErrNegative is returned when a negative integer is given for a height or a
// round.
var ErrNegative = errors.New("types: negative height or round")

// Height is a block number or a consensus sequence. It is an
// arbitrary-precision non-negative integer, like the *big.Int of the reference
// implementation. A Height is immutable: arithmetic returns a new value. The
// zero value is 0.
//
// The truncating accessors RefLow64 and RefLowInt64 are used where the
// reference implementation reads only the low 64 bits of a number. Outside
// this package they are called only on lines that carry a
// "//wbft:low64 HH-nn" comment naming the site label (tools/lint/heightlow).
//
// Spec: WBFT-TYPE-010
type Height struct{ v *big.Int }

// HeightFromUint64 returns n as a Height.
func HeightFromUint64(n uint64) Height {
	return Height{new(big.Int).SetUint64(n)}
}

// HeightFromBig returns a copy of b as a Height. A nil b is 0.
func HeightFromBig(b *big.Int) (Height, error) {
	if b == nil {
		return Height{}, nil
	}
	if b.Sign() < 0 {
		return Height{}, ErrNegative
	}
	return Height{new(big.Int).Set(b)}, nil
}

// MustHeightFromBig is HeightFromBig for values known to be non-negative. It
// panics on a negative value.
func MustHeightFromBig(b *big.Int) Height {
	h, err := HeightFromBig(b)
	if err != nil {
		panic(err)
	}
	return h
}

func (h Height) big() *big.Int {
	if h.v == nil {
		return new(big.Int)
	}
	return h.v
}

// Cmp compares h and o and returns -1, 0 or +1.
func (h Height) Cmp(o Height) int { return h.big().Cmp(o.big()) }

// CmpUint64 compares h with n.
func (h Height) CmpUint64(n uint64) int { return h.big().Cmp(new(big.Int).SetUint64(n)) }

// AddUint64 returns h + d.
func (h Height) AddUint64(d uint64) Height {
	return Height{new(big.Int).Add(h.big(), new(big.Int).SetUint64(d))}
}

// Sub returns h - o and true, or the zero value and false when the result
// would be negative.
func (h Height) Sub(o Height) (Height, bool) {
	r := new(big.Int).Sub(h.big(), o.big())
	if r.Sign() < 0 {
		return Height{}, false
	}
	return Height{r}, true
}

// IsZero reports whether h is 0.
func (h Height) IsZero() bool { return h.big().Sign() == 0 }

// Big returns h as a new *big.Int.
func (h Height) Big() *big.Int { return new(big.Int).Set(h.big()) }

// Bytes returns the minimal big-endian encoding of h (empty for 0), as
// big.Int.Bytes does.
func (h Height) Bytes() []byte { return h.big().Bytes() }

// IsUint64 reports whether h fits in 64 bits.
func (h Height) IsUint64() bool { return h.big().IsUint64() }

// String returns h in decimal.
func (h Height) String() string { return h.big().String() }

// RefLow64 returns the low 64 bits of h, exactly as big.Int.Uint64 does in the
// reference implementation. Call it only at the places where the reference
// truncates, with a "//wbft:low64 HH-nn" comment.
func (h Height) RefLow64() uint64 { return h.big().Uint64() }

// RefLowInt64 returns big.Int.Int64 of h: the low 64 bits read as a signed
// integer. Call it only where the reference calls Int64.
func (h Height) RefLowInt64() int64 { return h.big().Int64() }

// Round is a consensus round: an arbitrary-precision non-negative integer
// with the same representation and rules as Height.
//
// Spec: WBFT-TYPE-012
type Round struct{ v *big.Int }

// RoundFromUint64 returns r as a Round.
func RoundFromUint64(r uint64) Round {
	return Round{new(big.Int).SetUint64(r)}
}

// RoundFromBig returns a copy of b as a Round. A nil b is 0.
func RoundFromBig(b *big.Int) (Round, error) {
	if b == nil {
		return Round{}, nil
	}
	if b.Sign() < 0 {
		return Round{}, ErrNegative
	}
	return Round{new(big.Int).Set(b)}, nil
}

func (r Round) big() *big.Int {
	if r.v == nil {
		return new(big.Int)
	}
	return r.v
}

// Cmp compares r and o and returns -1, 0 or +1.
func (r Round) Cmp(o Round) int { return r.big().Cmp(o.big()) }

// AddUint64 returns r + d.
func (r Round) AddUint64(d uint64) Round {
	return Round{new(big.Int).Add(r.big(), new(big.Int).SetUint64(d))}
}

// IsZero reports whether r is 0.
func (r Round) IsZero() bool { return r.big().Sign() == 0 }

// Big returns r as a new *big.Int.
func (r Round) Big() *big.Int { return new(big.Int).Set(r.big()) }

// String returns r in decimal.
func (r Round) String() string { return r.big().String() }

// RefLow64 returns big.Int.Uint64 of r, the value the reference passes to
// proposer selection and round timers.
func (r Round) RefLow64() uint64 { return r.big().Uint64() }

// RefLow32 returns uint32(big.Int.Uint64()) of r, the value the reference
// stores in the header round fields and signs in seal_data (r mod 2^32).
func (r Round) RefLow32() uint32 { return uint32(r.big().Uint64()) }

// View is the pair (sequence, round) of a consensus step. Views are ordered
// by sequence first, then round, on the full values.
type View struct {
	Sequence Height
	Round    Round
}

// Cmp compares v and o and returns -1, 0 or +1.
//
// Spec: WBFT-TYPE-020
func (v View) Cmp(o View) int {
	if c := v.Sequence.Cmp(o.Sequence); c != 0 {
		return c
	}
	return v.Round.Cmp(o.Round)
}
