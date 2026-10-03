// Package evidence keeps the double-signing evidence a node detects: two
// messages of one signer for one view and code with different digests
// (observe.md 6, R-08). The node records it and serves it through
// wbft_evidence; it does not punish.
//
// The store is node-local: JSON Lines appended to a current file that is
// renamed to a numbered file at a size limit. A numbered file is removed
// once its newest record is older than the age limit.
package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/0xmhha/wbft/internal/fsys"
)

// Record is one piece of evidence.
type Record struct {
	Height  string    `json:"height"` // decimal, the full value
	Round   string    `json:"round"`  // decimal
	Code    uint64    `json:"code"`
	Kind    string    `json:"kind"` // "equivocation" or "round0_preprepare"
	Source  string    `json:"source"`
	DigestA string    `json:"digestA"`
	DigestB string    `json:"digestB"`
	SigA    string    `json:"sigA"`
	SigB    string    `json:"sigB"`
	Time    time.Time `json:"time"` // when the node detected it
}

// Options bound the store.
type Options struct {
	MaxFileBytes int64            // size at which the current file is rotated; default 16 MiB
	MaxAge       time.Duration    // age after which a rotated file is removed; default 30 days
	Now          func() time.Time // default time.Now
}

const (
	current = "evidence.jsonl"
	prefix  = "evidence-"
)

// Store is the evidence store of a node. It is safe for concurrent use.
type Store struct {
	fs   fsys.FS
	dir  string
	opts Options

	mu   sync.Mutex
	next int // number of the next rotated file
}

// Open opens the store in dir, creating it, and removes the rotated files
// past the age limit.
func Open(f fsys.FS, dir string, o Options) (*Store, error) {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 16 << 20
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 30 * 24 * time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := f.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{fs: f, dir: dir, opts: o}
	names, err := s.rotated()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		var k int
		if _, err := fmt.Sscanf(n, prefix+"%d.jsonl", &k); err == nil && k >= s.next {
			s.next = k + 1
		}
	}
	return s, s.prune()
}

// rotated returns the names of the rotated files, oldest first.
func (s *Store) rotated() ([]string, error) {
	names, err := s.fs.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names { // ReadDir sorts; the numbers are zero-padded
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".jsonl") {
			out = append(out, n)
		}
	}
	return out, nil
}

// Add appends a record, rotating the current file at the size limit.
func (s *Store) Add(r Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	name := path.Join(s.dir, current)
	if size, err := s.fs.Size(name); err == nil && size > 0 && size+int64(len(line)) > s.opts.MaxFileBytes {
		if err := s.fs.Rename(name, path.Join(s.dir, fmt.Sprintf(prefix+"%08d.jsonl", s.next))); err != nil {
			return err
		}
		s.next++
		if err := s.prune(); err != nil {
			return err
		}
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
	return f.Close()
}

// prune removes the rotated files whose newest record is past the age
// limit; s.mu is held or the store is not shared yet.
func (s *Store) prune() error {
	names, err := s.rotated()
	if err != nil {
		return err
	}
	limit := s.opts.Now().Add(-s.opts.MaxAge)
	for _, n := range names {
		recs, err := s.read(n)
		if err != nil {
			return err
		}
		if len(recs) == 0 || recs[len(recs)-1].Time.Before(limit) {
			if err := s.fs.Remove(path.Join(s.dir, n)); err != nil {
				return err
			}
		}
	}
	return nil
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
	for _, l := range bytes.Split(b, []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(l, &r); err != nil {
			continue // a torn last line after a crash
		}
		out = append(out, r)
	}
	return out, nil
}

// Range returns the records of the heights from..to, oldest file first and
// in the order they were added.
func (s *Store) Range(from, to *big.Int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := s.rotated()
	if err != nil {
		return nil, err
	}
	out := []Record{}
	for _, n := range append(names, current) {
		recs, err := s.read(n)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			h, ok := new(big.Int).SetString(r.Height, 10)
			if ok && h.Cmp(from) >= 0 && h.Cmp(to) <= 0 {
				out = append(out, r)
			}
		}
	}
	return out, nil
}
