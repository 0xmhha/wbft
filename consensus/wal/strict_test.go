package wal

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/internal/fsys"
)

// This is a detached unsigned byte-array model, never a stored signed WAL.
// Its mutation methods only count calls; they cannot change a filesystem.
type strictReadModel struct {
	files   map[string][]byte
	exists  bool
	readErr error
	dirErr  error
	writes  int
}

func (m *strictReadModel) ReadDir(string) ([]string, error) {
	if m.dirErr != nil {
		return nil, m.dirErr
	}
	if !m.exists {
		return nil, fsys.ErrNotExist
	}
	var names []string
	for name := range m.files {
		names = append(names, name)
	}
	return names, nil
}
func (m *strictReadModel) ReadFile(name string) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	b, ok := m.files[filepath.Base(name)]
	if !ok {
		return nil, fsys.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (m *strictReadModel) Size(name string) (int64, error) {
	b, err := m.ReadFile(name)
	return int64(len(b)), err
}
func (m *strictReadModel) mutation() error { m.writes++; return errors.New("read-only model") }
func (m *strictReadModel) OpenFile(string, int, fs.FileMode) (fsys.File, error) {
	return nil, m.mutation()
}
func (m *strictReadModel) MkdirAll(string, fs.FileMode) error { return m.mutation() }
func (m *strictReadModel) Rename(string, string) error        { return m.mutation() }
func (m *strictReadModel) Remove(string) error                { return m.mutation() }
func (m *strictReadModel) SyncDir(string) error               { return m.mutation() }

func TestStrictInspectionRejectsIncompleteUnsignedFramesWithoutMutation(t *testing.T) {
	complete, err := Encode(Record{Format: 1, Kind: 2, Body: []byte("unsigned metadata")})
	if err != nil {
		t.Fatal(err)
	}
	crc := bytes.Clone(complete)
	crc[4] ^= 1
	length := []byte{0, 0, 0, 1, 0, 0, 0, 0, 1}
	cases := map[string]map[string][]byte{
		"last partial header": {segmentName(0): []byte{0, 0, 0}},
		"last partial body":   {segmentName(0): complete[:len(complete)-1]},
		"middle partial":      {segmentName(0): []byte{0}, segmentName(1): complete},
		"bad checksum":        {segmentName(0): crc},
		"bad length":          {segmentName(0): length},
		"marker only":         {segmentName(0) + corruptedSuffix: nil},
		"marker and healthy":  {segmentName(0) + corruptedSuffix: nil, segmentName(1): complete},
		"overflow":            {"18446744073709551615.wal": nil},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			m := &strictReadModel{files: files, exists: true}
			if _, err := Inspect(m, "/model"); err == nil {
				t.Fatal("incomplete source accepted")
			}
			if _, _, err := OpenStrict(m, "/model", Options{}); err == nil {
				t.Fatal("incomplete source opened")
			}
			if m.writes != 0 {
				t.Fatal("inspection mutated source", m.writes)
			}
		})
	}
}

func TestStrictSnapshotDeepCopiesAndRejectsChangedModel(t *testing.T) {
	frame, err := Encode(Record{Format: 1, Kind: 2, Body: []byte("unsigned")})
	if err != nil {
		t.Fatal(err)
	}
	m := &strictReadModel{files: map[string][]byte{segmentName(2): frame, segmentName(7): frame}, exists: true}
	s, err := Inspect(m, "/model")
	if err != nil || m.writes != 0 {
		t.Fatal(err, m.writes)
	}
	records, positions := s.Records()
	if len(records) != 2 || positions[0].Segment != 2 || positions[1].Segment != 7 {
		t.Fatal("unordered source", positions)
	}
	records[0].Body[0] = 'X'
	positions[0].Segment = 100
	again, places := s.Records()
	if !bytes.Equal(again[0].Body, []byte("unsigned")) || places[0].Segment != 2 {
		t.Fatal("snapshot was externally mutable")
	}
	// Switch the detached model's manifest, without writing or altering a WAL.
	m.files = map[string][]byte{segmentName(2): frame}
	if _, _, err := s.Open(Options{}); !errors.Is(err, ErrSourceChanged) {
		t.Fatal("changed manifest accepted", err)
	}
	if m.writes != 0 {
		t.Fatal("changed source reached a writer")
	}
}

func TestStrictSnapshotFreshAndReadErrors(t *testing.T) {
	for _, which := range []string{"permission", "read", "missing to directory"} {
		t.Run(which, func(t *testing.T) {
			m := &strictReadModel{}
			switch which {
			case "permission":
				m.dirErr = fs.ErrPermission
			case "read":
				m.exists, m.files, m.readErr = true, map[string][]byte{segmentName(0): nil}, fs.ErrPermission
			case "missing to directory":
				s, err := Inspect(m, "/model")
				if err != nil {
					t.Fatal(err)
				}
				m.exists = true
				if _, _, err := s.Open(Options{}); !errors.Is(err, ErrSourceChanged) {
					t.Fatal(err)
				}
			}
			if which != "missing to directory" {
				if _, err := Inspect(m, "/model"); !errors.Is(err, fs.ErrPermission) {
					t.Fatal("read error became fresh", err)
				}
			}
			if m.writes != 0 {
				t.Fatal("read-only refusal wrote", m.writes)
			}
		})
	}
	if _, _, err := new(Snapshot).Open(Options{}); err == nil {
		t.Fatal("zero snapshot authorized writes")
	}
}

func TestStrictOpenNormalAppendAndSnapshotReuse(t *testing.T) {
	m := fsys.NewMem()
	s, err := Inspect(m, "/normal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadDir("/normal"); !fsys.IsNotExist(err) {
		t.Fatal("fresh inspection created directory", err)
	}
	log, rec, err := s.Open(Options{SegmentBytes: 64})
	if err != nil || !log.OpenedStrict() || rec.Segments != 0 {
		t.Fatal(rec, err)
	}
	if _, _, err := s.Open(Options{}); !errors.Is(err, ErrSourceChanged) {
		t.Fatal("snapshot reused while open", err)
	}
	var want []Record
	for i := 0; i < 9; i++ {
		r := Record{Format: 1, Kind: 2, Body: []byte(fmt.Sprint("unsigned-", i))}
		want = append(want, r)
		if _, err := log.AppendSync(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(Options{}); !errors.Is(err, ErrSourceChanged) {
		t.Fatal("snapshot reused after close", err)
	}
	before, err := Segments(m, "/normal")
	if err != nil {
		t.Fatal(err)
	}
	opened, rec, err := OpenStrict(m, "/normal", Options{})
	if err != nil || rec.Records != len(want) || rec.TornBytes != 0 || len(rec.Corrupted) != 0 {
		t.Fatal(rec, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	got, _, err := ReadAll(m, "/normal")
	if err != nil || !equalRecords(want, got) {
		t.Fatal("ordinary reopen changed records", err)
	}
	after, err := Segments(m, "/normal")
	if err != nil || len(after) != len(before)+1 || !slices.Equal(before, after[:len(before)]) {
		t.Fatal("old segments changed", err)
	}
}

func TestStrictRotationExhaustionPrecedesFileEffects(t *testing.T) {
	// A closed logical counter model, with no opened file or stored records.
	m := &strictReadModel{}
	log := &Log{strict: true, seg: ^uint64(0), fs: m, buf: []byte("unsigned")}
	if err := log.Rotate(); err == nil {
		t.Fatal("strict segment counter wrapped")
	}
	if m.writes != 0 || !bytes.Equal(log.buf, []byte("unsigned")) {
		t.Fatal("exhausted counter reached a file effect")
	}
}
