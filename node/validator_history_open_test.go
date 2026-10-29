package node

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
)

// Detached unsigned metadata, exposed as reads only. No live WAL is
// truncated, corrupted or replayed with another signing identity.
type startupReadModel struct {
	fsys.FS
	data   []byte
	writes int
}

type startupKeyReads struct {
	fsys.FS
	path  string
	reads int
}

func (s *startupKeyReads) ReadFile(path string) ([]byte, error) {
	if path == s.path {
		s.reads++
	}
	return s.FS.ReadFile(path)
}

func TestValidatorHistoryNodeReadsNormalKeyOnce(t *testing.T) {
	key := testKey(0)
	config, genesis := testGenesis(t, key)
	a := newTestApp(config, genesis)
	mem := fsys.NewMem()
	if err := mem.MkdirAll("/keys", 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := mem.OpenFile("/keys/node", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(privval.FormatKeyFile(key)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	store := &startupKeyReads{FS: mem, path: "/keys/node"}
	n, err := New(Config{DataDir: "/normal-key", KeyFile: store.path, Improvements: []string{"defer_validator_start"}},
		Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: store, clock: cacheObservationClock{}})
	if err != nil {
		t.Fatal(err)
	}
	a.cons = n.Consensus()
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	parsed, err := ecdsa.PrivateKeyFromBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	if store.reads != 1 || n.Address() != ecdsa.Address(parsed) {
		t.Fatal("startup reread key or changed identity", store.reads)
	}
}

func (m *startupReadModel) ReadDir(dir string) ([]string, error) {
	if filepath.Base(dir) == walDir {
		return []string{"00000000000000000000.wal"}, nil
	}
	return nil, fsys.ErrNotExist
}
func (m *startupReadModel) ReadFile(string) ([]byte, error) { return bytes.Clone(m.data), nil }
func (m *startupReadModel) Size(string) (int64, error)      { return int64(len(m.data)), nil }
func (m *startupReadModel) mutation() error {
	m.writes++
	return errors.New("read-only unsigned model")
}
func (m *startupReadModel) OpenFile(string, int, fs.FileMode) (fsys.File, error) {
	return nil, m.mutation()
}
func (m *startupReadModel) MkdirAll(string, fs.FileMode) error { return m.mutation() }
func (m *startupReadModel) Rename(string, string) error        { return m.mutation() }
func (m *startupReadModel) Remove(string) error                { return m.mutation() }
func (m *startupReadModel) SyncDir(string) error               { return m.mutation() }

func TestValidatorHistoryNodePreflightPrecedesPersistentWriters(t *testing.T) {
	legacy, err := wal.Encode(wal.Record{Format: 1, Kind: 1, Body: []byte("unsigned metadata")})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{{0, 0, 0}, legacy} {
		key := testKey(0)
		config, genesis := testGenesis(t, key)
		a := newTestApp(config, genesis)
		store := &startupReadModel{data: raw}
		n, err := New(Config{DataDir: "/preflight", Improvements: []string{"defer_validator_start"}, TakeoverGuard: true},
			Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: store, key: key, clock: cacheObservationClock{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(t.Context()); err == nil {
			_ = n.Stop()
			t.Fatal("unsupported prefix started node")
		}
		if store.writes != 0 || n.signer != nil || n.wal != nil || n.rej != nil || n.part != nil || n.evid != nil || !bytes.Equal(raw, store.data) {
			t.Fatal("refusal reached a persistent writer", store.writes)
		}
	}
}
