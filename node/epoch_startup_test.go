package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func epochStartupJSON(t *testing.T, raw []byte, length uint64, transitions string) []byte {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var anzeon map[string]json.RawMessage
	if err := json.Unmarshal(cfg["anzeon"], &anzeon); err != nil {
		t.Fatal(err)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(anzeon["wbft"], &params); err != nil {
		t.Fatal(err)
	}
	params["epochLength"] = json.RawMessage(fmt.Sprintf("%d", length))
	anzeon["wbft"], _ = json.Marshal(params)
	cfg["anzeon"], _ = json.Marshal(anzeon)
	cfg["transitions"] = json.RawMessage(transitions)
	result, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type epochStartupFS struct {
	fsys.FS
	writeOpens atomic.Int64
}

func (s *epochStartupFS) OpenFile(name string, flag int, mode fs.FileMode) (fsys.File, error) {
	if flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR) != 0 {
		s.writeOpens.Add(1)
	}
	return s.FS.OpenFile(name, flag, mode)
}

func TestNodeEpochScheduleAdmission(t *testing.T) {
	for _, tc := range []struct {
		name        string
		length      uint64
		transitions string
		refuse      bool
	}{
		{"base-one", 1, `[]`, true},
		{"transition-one", 4, `[{"block":6,"epochLength":1}]`, true},
		{"adjacent", 4, `[{"block":5,"epochLength":4}]`, true},
		{"full-width-adjacent", 4, `[{"block":18446744073709551617,"epochLength":4}]`, true},
		{"minimum-control", 2, `[]`, false},
		{"two-block-control", 4, `[{"block":6,"epochLength":2}]`, false},
		{"same-block-control", 4, `[{"block":6,"epochLength":2},{"block":6,"epochLength":4}]`, false},
	} {
		for _, standalone := range []bool{false, true} {
			for _, signing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/standalone=%v/signing=%v", tc.name, standalone, signing), func(t *testing.T) {
					key := testKey(0)
					raw, g := testGenesis(t, key)
					a := newTestApp(epochStartupJSON(t, raw, tc.length, tc.transitions), g)
					storage := &epochStartupFS{FS: fsys.NewMem()}
					d := Deps{App: a, Authority: a, fs: storage}
					if signing {
						d.key = key
					}
					n, err := New(Config{DataDir: "/data", Standalone: standalone}, d)
					if err != nil {
						t.Fatal(err)
					}
					a.cons = n.Consensus()
					err = n.Start(context.Background())
					if tc.refuse {
						if !errors.Is(err, ErrStartRefused) {
							if err == nil {
								stop(t, n)
							}
							t.Fatalf("expected startup refusal: %v", err)
						}
						if storage.writeOpens.Load() != 0 {
							t.Fatal("invalid schedule opened writable state before refusal")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					stop(t, n)
				})
			}
		}
	}
}

func TestSameBlockTransitionsWarnAndPreserveOrder(t *testing.T) {
	key := testKey(0)
	raw, g := testGenesis(t, key)
	raw = epochStartupJSON(t, raw, 4, `[{"block":6,"epochLength":2},{"block":6,"epochLength":4},{"block":10,"epochLength":2},{"block":10,"epochLength":3}]`)
	a := newTestApp(raw, g)
	var events syncBuffer
	var logs bytes.Buffer
	n, err := New(Config{DataDir: "/data"}, Deps{App: a, Authority: a, fs: fsys.NewMem(), Events: &events, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err = n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop(t, n)
	checkEvents([]byte(events.String()))
	if got := n.chainCfg.ConfigAt(types.HeightFromUint64(6)).EpochLength; got != 4 {
		t.Fatalf("same-block order changed: %d", got)
	}
	if got := n.chainCfg.ConfigAt(types.HeightFromUint64(10)).EpochLength; got != 3 {
		t.Fatalf("later same-block order changed: %d", got)
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var r struct{ Kind, What, Reason string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Kind == "HEALTH" && r.What == "same_block_transitions" {
			count++
			if !strings.Contains(r.Reason, "2 transitions at block") {
				t.Fatalf("warning lost context: %s", r.Reason)
			}
		}
	}
	if count != 2 || strings.Count(logs.String(), "multiple transitions share a block") != 2 {
		t.Fatalf("warnings: health=%d logs=%s", count, logs.String())
	}
	if !strings.Contains(strings.Split(events.String(), "\n")[0], `"kind":"NODE_START"`) {
		t.Fatal("warning preceded the run boundary")
	}
}
