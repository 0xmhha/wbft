// Package rejection keeps the blocks and proposals a node rejected, with
// the step that failed, its error class and the path the block came by
// (observe.md 6, R-09). The reference keeps only its ten highest bad blocks
// and no step.
//
// The store is node-local: JSON Lines appended to a current file that
// replaces the previous file once it holds half the record limit, so the
// most recent records, between half and all of the limit, are kept.
package rejection

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path"
	"sync"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
)

// Record is one rejection.
type Record struct {
	Number string    `json:"number"` // decimal, the full value
	Hash   string    `json:"hash"`
	Step   string    `json:"step"`       // "P1".."P7", "V0a", "V0b", "H1".."H21" or a Part B step; empty when unknown
	Class  string    `json:"errorClass"` // the specification error name; empty when unknown
	Path   string    `json:"path"`       // "preprepare", "sealed_locally", "imported" or "synced"
	Time   time.Time `json:"time"`
}

// Options bound the store.
type Options struct {
	MaxRecords int // the records kept at most; default 10 000
}

const (
	current  = "rejections.jsonl"
	previous = "rejections.prev.jsonl"
)

// Store is the rejection store of a node. It is safe for concurrent use.
type Store struct {
	fs   fsys.FS
	dir  string
	half int

	mu sync.Mutex
	n  int // records in the current file
}

// Open opens the store in dir, creating it.
func Open(f fsys.FS, dir string, o Options) (*Store, error) {
	if o.MaxRecords <= 0 {
		o.MaxRecords = 10_000
	}
	if err := f.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{fs: f, dir: dir, half: max(o.MaxRecords/2, 1)}
	recs, err := s.read(current)
	if err != nil {
		return nil, err
	}
	s.n = len(recs)
	return s, nil
}

// Add appends a record, replacing the previous file by the current one
// when the current one is full.
func (s *Store) Add(r Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	name := path.Join(s.dir, current)
	if s.n >= s.half {
		if err := s.fs.Rename(name, path.Join(s.dir, previous)); err != nil {
			return err
		}
		s.n = 0
	}
	f, err := s.fs.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	s.n++
	return f.Close()
}

func (s *Store) read(name string) ([]Record, error) {
	b, err := s.fs.ReadFile(path.Join(s.dir, name))
	if err != nil {
		if fsys.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r) // a torn last line after a crash is skipped
		}
	}
	return out, sc.Err()
}

// Range returns the records of the block numbers from..to, older first.
func (s *Store) Range(from, to *big.Int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Record{}
	for _, name := range []string{previous, current} {
		recs, err := s.read(name)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			n, ok := new(big.Int).SetString(r.Number, 10)
			if ok && n.Cmp(from) >= 0 && n.Cmp(to) <= 0 {
				out = append(out, r)
			}
		}
	}
	return out, nil
}
