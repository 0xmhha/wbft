package validator

import (
	"math/big"
	"testing"
)

func TestIntegerQuorumSize(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 7, 10000, 3<<50 + 3, int(^uint(0) >> 1)} {
		want := big.NewInt(int64(n))
		want.Mul(want, big.NewInt(2)).Quo(want, big.NewInt(3)).Add(want, big.NewInt(1))
		if got := IntegerQuorumSize(n); int64(got) != want.Int64() {
			t.Fatalf("size %d: got %d, want %s", n, got, want)
		}
	}
}
