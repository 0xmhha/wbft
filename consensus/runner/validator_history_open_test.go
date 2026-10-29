package runner

import (
	"bytes"
	"errors"
	"io/fs"
	"testing"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
)

// A closed unsigned metadata array exposed through read-only filesystem
// methods. Refusals cannot change an existing runtime WAL or signer.
type historyReadModel struct {
	fsys.FS
	data   []byte
	writes int
}

func (m *historyReadModel) ReadDir(string) ([]string, error) {
	return []string{"00000000000000000000.wal"}, nil
}
func (m *historyReadModel) ReadFile(string) ([]byte, error) { return bytes.Clone(m.data), nil }
func (m *historyReadModel) Size(string) (int64, error)      { return int64(len(m.data)), nil }
func (m *historyReadModel) mutation() error {
	m.writes++
	return errors.New("read-only unsigned model")
}
func (m *historyReadModel) OpenFile(string, int, fs.FileMode) (fsys.File, error) {
	return nil, m.mutation()
}
func (m *historyReadModel) MkdirAll(string, fs.FileMode) error { return m.mutation() }
func (m *historyReadModel) Rename(string, string) error        { return m.mutation() }
func (m *historyReadModel) Remove(string) error                { return m.mutation() }
func (m *historyReadModel) SyncDir(string) error               { return m.mutation() }

func TestValidatorHistoryPreflightBindsSemanticSourceBeforeWriters(t *testing.T) {
	m := newValidatorHistoryModel(t, true)
	var raw []byte
	for _, record := range m.frames {
		frame, err := wal.Encode(record)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, frame...)
	}
	store := &historyReadModel{data: raw}
	bad := m.r.cfg
	bad.Core.Self[0] ^= 1
	state, err := InspectWALForConfig(store, "/model", bad)
	if err == nil {
		t.Fatal("mismatched semantic profile accepted")
	}
	if _, _, err := state.OpenValidatedWAL(wal.Options{}); err == nil {
		t.Fatal("failed inspection retained open capability")
	}
	state, err = InspectWALForConfig(store, "/model", m.r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	headerCalled := false
	if _, _, err := state.OpenValidatedWAL(wal.Options{Header: func() []wal.Record { headerCalled = true; return nil }}); err == nil {
		t.Fatal("unsupported header opened selected history")
	}
	if headerCalled || store.writes != 0 || !bytes.Equal(raw, store.data) {
		t.Fatal("preflight caused a writer")
	}
	// Public handshake fields do not manufacture the private capability.
	forged := WALState{LastEnd: state.LastEnd, Commits: state.Commits}
	if _, _, err := forged.OpenValidatedWAL(wal.Options{}); err == nil {
		t.Fatal("public fields authorized an open")
	}
}

func TestValidatorHistoryRejectsRepairCapableLog(t *testing.T) {
	m := newValidatorHistoryModel(t, true)
	for _, strict := range []bool{false, true} {
		open := wal.Open
		if strict {
			open = wal.OpenStrict
		}
		log, _, err := open(fsys.NewMem(), "/fresh-unsigned", wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		cfg := m.r.cfg
		err = freezeValidatorHistoryConfig(&cfg, log)
		if (err == nil) != strict {
			t.Fatal("wrong open capability accepted", strict, err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
