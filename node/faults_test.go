//go:build wbft_faults

package node

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
)

// crash is the panic value of the fault handler.
type crash struct{}

// TestSignFloorCrash crashes a node with a taken-over key before and after
// its sign floor reaches the disk. The restarted node sets or keeps the
// floor and signs nothing at H_app + 1.
func TestSignFloorCrash(t *testing.T) {
	key := testKey(0)
	cj, g := testGenesis(t, key)
	a := newTestApp(cj, g)
	n := startNode(t, a, fsys.NewMem(), key, true, nil)
	a.waitHead(t, 2, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{faultpoint.PrivvalBeforePersist, faultpoint.PrivvalAfterPersist} {
		t.Run(point, func(t *testing.T) {
			fs := fsys.NewMem()
			n, err := New(Config{DataDir: "/data", TakeoverGuard: true}, Deps{App: a, Authority: a, fs: fs, key: key,
				faults: func(name string) {
					if name == point {
						panic(crash{})
					}
				}})
			if err != nil {
				t.Fatal(err)
			}
			a.cons = n.Consensus()
			func() {
				defer func() {
					if x := recover(); x == nil {
						t.Fatal("the node did not reach the fault point")
					} else if _, ok := x.(crash); !ok {
						panic(x)
					}
				}()
				_ = n.Start(context.Background())
			}()
			fs.Crash(rand.New(rand.NewPCG(1, 2)))
			checkTakeover(t, a, fs, key)
		})
	}
}
