package stepdriver

import (
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
	"math/big"
	"testing"
)

func TestTimedSnapshotPreservesFullWidthViewAndStoppedAbsence(t *testing.T) {
	h, _ := new(big.Int).SetString("90071992547409931234567890", 10)
	r, _ := new(big.Int).SetString("90071992547409941234567891", 10)
	height, err := types.HeightFromBig(h)
	if err != nil {
		t.Fatal(err)
	}
	round, err := types.RoundFromBig(r)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &consensus.Snapshot{Running: true, View: types.View{Sequence: height, Round: round}, State: consensus.Committed}
	out := timedSnapshot(snapshot)
	if out.Height == nil || out.Round == nil || *out.Height != h.String() || *out.Round != r.String() || out.State != "Committed" {
		t.Fatal(out)
	}
	snapshot.Running = false
	out = timedSnapshot(snapshot)
	if out.Running || out.Height != nil || out.Round != nil || out.State != "" {
		t.Fatal("stopped stale view leaked", out)
	}
}
