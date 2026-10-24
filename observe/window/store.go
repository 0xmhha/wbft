// Package window persists explicit observation checkpoints. It neither
// selects a trusted chain anchor nor registers or restarts a running observer.
package window

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/types"
)

// Save atomically replaces a checkpoint in an existing caller-owned directory.
// Callers serialize saves to one path. Success means file sync, rename and
// directory sync completed; it does not certify hardware power-loss behavior.
func Save(path string, engine *state.Engine, s *state.State, trusted *types.Header) error {
	if engine == nil {
		return state.ErrPolicy
	}
	raw, err := engine.EncodeCheckpoint(s, trusted)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".observation-checkpoint-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = io.Copy(f, bytes.NewReader(raw)); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Load bounds reads from one opened file and verifies its contents against a
// caller-trusted carrier. Checkpoint data cannot supply its own trust anchor.
func Load(path string, engine *state.Engine, trusted *types.Header) (*state.State, error) {
	if engine == nil {
		return nil, state.ErrPolicy
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(engine.CheckpointLimit())+1))
	if err != nil {
		return nil, err
	}
	return engine.Recover(raw, trusted)
}
