package sim

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
)

func TestValidatorHistorySimulationPreflightPrecedesIncarnation(t *testing.T) {
	// These fresh inputs are unsigned fixture metadata, never existing
	// consensus WALs. No actor, storage fault or signed replay is invoked.
	legacy, err := wal.Encode(wal.Record{Format: 1, Kind: 1, Body: []byte("unsigned metadata")})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{{0, 0, 0}, legacy} {
		sc := timingCompatibilityScenario(t, 2)
		sc.Schedule = nil
		sc.Nodes[0].Options.Improvements = sc.Nodes[0].Options.Improvements.With(consensus.DeferValidatorStart)
		s, err := newSimulation(sc)
		if err != nil {
			t.Fatal(err)
		}
		n := s.nodes[0]
		if err := n.fs.MkdirAll(walDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(walDir, "00000000000000000000.wal")
		file, err := n.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		n.start()
		if n.inc != 0 || n.alive || !n.down || len(n.eventFiles) != 0 || n.log != nil || n.signer != nil || n.jw != nil {
			t.Fatal("refusal started a lifecycle")
		}
		got, err := n.fs.ReadFile(path)
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatal("unsigned source changed", err)
		}
		names, err := n.fs.ReadDir(walDir)
		if err != nil || len(names) != 1 || names[0] != filepath.Base(path) {
			t.Fatal("refusal changed segment manifest", err)
		}
	}
}
