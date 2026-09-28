package sim

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// round0Rate is the share of heights decided in round 0.
func round0Rate(res *Result) float64 {
	if len(res.Rounds) == 0 {
		return 0
	}
	n := 0
	for _, r := range res.Rounds {
		if r == 0 {
			n++
		}
	}
	return float64(n) / float64(len(res.Rounds))
}

// maxHonestLatency is the longest wait of a message of an honest peer
// between its arrival and its core step, from the node journals.
func maxHonestLatency(t *testing.T, res *Result, flooder types.Address) time.Duration {
	var worst time.Duration
	for node, files := range res.Journals {
		if node == flooder {
			continue
		}
		fs := fsys.NewMem()
		_ = fs.MkdirAll("/j", 0o700)
		for name, data := range files {
			f, _ := fs.OpenFile(filepath.Join("/j", name), os.O_WRONLY|os.O_CREATE, 0o600)
			_, _ = f.Write(data)
			_ = f.Close()
		}
		recs, err := journal.ReadAll(fs, "/j")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			s, ok := r.Body.(*journal.StepRec)
			if !ok || s.InputKind != inputlog.KindMessage || s.Via != "peer" {
				continue
			}
			in, err := inputlog.Decode(s.InputKind, s.Input, nil)
			if err != nil {
				t.Fatal(err)
			}
			m := in.(consensus.Message)
			if m.Peer == flooder {
				continue
			}
			worst = max(worst, s.Mono-m.RecvMono)
		}
	}
	return worst
}

// A validator that floods one node with validly signed messages does not
// delay the messages of the other peers by more than a tenth of the round
// timer, and the share of heights decided in round 0 does not fall by more
// than five points. The simulator gives receive checks and core steps no
// processing time, so the waits measured here come from queueing order
// alone.
func TestFloodJudgements(t *testing.T) {
	keys := testValidators(t, 7)
	n := seedCount(t, 3)
	var with, without float64
	var worst time.Duration
	for seed := int64(0); seed < int64(n); seed++ {
		sc := validFlood(seed, keys)
		sc.Schedule = nil // no restarts: compare like with like
		flooder := sc.Adversaries[0].Node
		a, err := Run(context.Background(), sc, Output{})
		if err != nil || len(a.Violations) > 0 {
			t.Fatal(err, a.Violations)
		}
		sc.Adversaries = nil
		b, err := Run(context.Background(), sc, Output{})
		if err != nil || len(b.Violations) > 0 {
			t.Fatal(err, b.Violations)
		}
		with += round0Rate(a)
		without += round0Rate(b)
		worst = max(worst, maxHonestLatency(t, a, flooder))
	}
	with, without = with/float64(n), without/float64(n)
	t.Logf("round-0 share with flood %.3f, without %.3f; longest wait of an honest message %s", with, without, worst)
	if without-with > 0.05 {
		t.Fatalf("round-0 share fell by %.3f", without-with)
	}
	if worst > 200*time.Millisecond {
		t.Fatalf("an honest message waited %s", worst)
	}
}

// A peer that overflows its receive queue is the only one disconnected.
func TestOverflowDisconnectsOnlyTheFlooder(t *testing.T) {
	keys := testValidators(t, 7)
	for seed := int64(0); seed < int64(seedCount(t, 4)); seed++ {
		sc := inboundOverflow(seed, keys)
		flooder := sc.Adversaries[0].Node
		res, err := Run(context.Background(), sc, Output{})
		if err != nil || len(res.Violations) > 0 {
			t.Fatal(err, res.Violations)
		}
		var peers []string
		for _, data := range res.Events {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var m map[string]any
				if json.Unmarshal([]byte(line), &m) != nil {
					continue
				}
				if m["kind"] == "HEALTH" && m["what"] == "peer_inbound_disconnect" {
					peers = append(peers, m["peer"].(string))
				}
			}
		}
		if len(peers) == 0 {
			t.Fatalf("seed %d: nobody disconnected", seed)
		}
		want := strings.ToLower(hexAddr(flooder))
		if slices.ContainsFunc(peers, func(p string) bool { return p != want }) {
			t.Fatalf("seed %d: disconnected %v, flooder %s", seed, peers, want)
		}
	}
}
