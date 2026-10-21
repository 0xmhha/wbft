package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
)

// Ordinary local configuration checks run before this node opens its durable
// consensus stores. The application itself is outside that storage claim.
func TestInitialRoundBudgetStartupPair(t *testing.T) {
	for _, row := range []struct {
		name            string
		request, period uint64
		transition      bool
		insufficient    bool
	}{
		{"base-less", 1, 2, false, true},
		{"base-equal", 1, 1, false, true},
		{"base-greater", 2, 1, false, false},
		{"future-equal", 2, 1, true, true},
	} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", row.name, enabled), func(t *testing.T) {
				raw, g := testGenesis(t, testKey(0))
				var config map[string]any
				if err := json.Unmarshal(raw, &config); err != nil {
					t.Fatal(err)
				}
				params := config["anzeon"].(map[string]any)["wbft"].(map[string]any)
				params["requestTimeoutSeconds"], params["blockPeriodSeconds"] = row.request, row.period
				if row.transition {
					config["transitions"] = []any{map[string]any{"block": 10, "requestTimeoutSeconds": 1}}
				}
				raw, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				a := newTestApp(raw, g)
				fs := fsys.NewMem()
				var names []string
				if enabled {
					names = []string{"require_initial_round_budget"}
				}
				n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a, fs: fs})
				if err != nil {
					t.Fatal(err)
				}
				a.cons = n.Consensus()
				err = n.Start(context.Background())
				blocked := enabled && row.insufficient
				if errors.Is(err, ErrStartRefused) != blocked || err != nil && !errors.Is(err, ErrStartRefused) {
					t.Fatal("selected initial budget", err)
				}
				if blocked {
					for _, path := range []string{walDir, privvalDir, rejectionDir} {
						if _, err = fs.ReadDir(filepath.Join("/data", path)); !fsys.IsNotExist(err) {
							t.Fatal("refused node opened consensus store", path, err)
						}
					}
				} else {
					stop(t, n)
				}
			})
		}
	}
}
