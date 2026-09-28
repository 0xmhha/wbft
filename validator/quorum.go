package validator

import "math"

// FValue is the fault threshold F of a validator set of size n, computed in
// IEEE-754 binary64 exactly as the reference does: float64(n-1) / 3 with one
// rounding. The explicit conversion keeps the result rounded to binary64
// before any later operation.
//
// Spec: WBFT-VAL-001
func FValue(n int) float64 {
	return float64(float64(n-1) / float64(3))
}

// QuorumSize is ceil(float64(n) - FValue(n)) with each binary64 operation
// rounded on its own. It equals (2n) div 3 + 1 for every n below 3·2^50 + 3,
// but the binary64 form is normative.
//
// Spec: WBFT-VAL-002
func QuorumSize(n int) int {
	f := FValue(n)
	d := float64(float64(n) - f)
	return int(math.Ceil(d))
}

// InFPlusOneWindow reports whether a count num of validators satisfies the
// early round-change window of the reference, float64(num) > F and
// float64(num) <= F + 1, evaluated in binary64.
//
// Spec: WBFT-VAL-003
func InFPlusOneWindow(num, n int) bool {
	f := FValue(n)
	x := float64(num)
	fp1 := float64(f + 1)
	return x > f && x <= fp1
}

// FPlusOneThreshold returns (n - 1) div 3 + 1 with floor division (0 for
// n = 0): the only count in the window of InFPlusOneWindow for every
// n below 2^53 + 2.
//
// Spec: WBFT-VAL-003
func FPlusOneThreshold(n int) int {
	if n <= 0 {
		return 0
	}
	return (n-1)/3 + 1
}
