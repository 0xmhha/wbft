package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/rpc"
)

func TestImportOptionsConstructionAndReporting(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	for _, names := range [][]string{nil, {"commit_watchdog"}, {"advance_on_commit_failure"}, {"commit_watchdog", "advance_on_commit_failure"}, {"reset_height_state"}, {"scan_ready_backlog"}, {"commit_watchdog", "advance_on_commit_failure", "reset_height_state", "scan_ready_backlog"}} {
		a := newTestApp(raw, genesis)
		var events bytes.Buffer
		original := append([]string(nil), names...)
		n, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a, fs: fsys.NewMem(), Events: &events})
		if err != nil {
			t.Fatal(err)
		}
		if len(names) > 0 {
			names[0] = "caller-mutated"
		}
		a.cons = n.Consensus()
		if err = n.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		stop(t, n)
		checkEvents(events.Bytes())
		info := (backend{n}).NodeInfo()
		configured := []string{}
		for _, item := range info.Improvements {
			if item.Source == "node" {
				configured = append(configured, item.Name)
			}
		}
		if len(original) != len(configured) || len(original) > 0 && !reflect.DeepEqual(original, configured) {
			t.Fatal("configured options not reported", original, configured)
		}
		for _, i := range []consensus.Improvement{consensus.OneRound0Proposal, consensus.BadBlockReleaseMark} {
			if !n.coreImprovements.Has(i) {
				t.Fatal("restart safety disabled")
			}
		}
		var start struct {
			Improvements []rpc.Improvement `json:"improvements"`
		}
		if err = json.Unmarshal(bytes.Split(events.Bytes(), []byte{'\n'})[0], &start); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(start.Improvements, info.Improvements) {
			t.Fatal("RPC and start options differ")
		}
	}
	for _, names := range [][]string{{"unknown"}, {"commit_watchdog", "commit_watchdog"}, {""}} {
		a := newTestApp(raw, genesis)
		if _, err := New(Config{DataDir: "/data", Improvements: names}, Deps{App: a, Authority: a}); !errors.Is(err, ErrConfig) {
			t.Fatal("unknown or duplicate options accepted", names, err)
		}
	}
}
