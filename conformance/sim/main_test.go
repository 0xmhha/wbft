package sim

import (
	"os"
	"testing"

	"github.com/0xmhha/wbft/crypto/bls"
)

// TestMain runs the simulations with single-threaded signature
// verification: the tests run many simulations at once.
func TestMain(m *testing.M) {
	bls.SetParallelism(1)
	os.Exit(m.Run())
}
