package participation

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/0xmhha/wbft/internal/fsys"
)

// bucketHeights is the number of heights one file of the store holds.
const bucketHeights = 256

const (
	filePrefix = "p-"
	fileSuffix = ".jsonl"
)

// store keeps the records as JSON Lines, one file per bucket of
// bucketHeights heights, named by the bucket number. A height written twice
// keeps the later line. Pruning removes whole files. It is safe for
// concurrent use.
type store struct {
	fs  fsys.FS
	dir string

	mu sync.Mutex
}

func openStore(f fsys.FS, dir string) (*store, error) {
	if err := f.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &store{fs: f, dir: dir}, nil
}

func bucketOf(h *big.Int) *big.Int { return new(big.Int).Div(h, big.NewInt(bucketHeights)) }

func (s *store) file(b *big.Int) string {
	return path.Join(s.dir, filePrefix+b.String()+fileSuffix)
}

// buckets returns the bucket numbers of the files in the store, ascending.
func (s *store) buckets() ([]*big.Int, error) {
	names, err := s.fs.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []*big.Int
	for _, n := range names {
		if !strings.HasPrefix(n, filePrefix) || !strings.HasSuffix(n, fileSuffix) {
			continue
		}
		if b, ok := new(big.Int).SetString(strings.TrimSuffix(strings.TrimPrefix(n, filePrefix), fileSuffix), 10); ok {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b *big.Int) int { return a.Cmp(b) })
	return out, nil
}

// put appends the record of height h. It does not sync: the store is
// observation data, and a crash may lose the last lines (participation.md 4).
func (s *store) put(h *big.Int, r *Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.fs.OpenFile(s.file(bucketOf(h)), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// prune removes the files whose heights are all below floor.
func (s *store) prune(floor *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bs, err := s.buckets()
	if err != nil {
		return err
	}
	for _, b := range bs {
		// The last height of bucket b is (b+1)*bucketHeights - 1.
		end := new(big.Int).Mul(new(big.Int).Add(b, big.NewInt(1)), big.NewInt(bucketHeights))
		if end.Cmp(floor) > 0 {
			break
		}
		if err := s.fs.Remove(s.file(b)); err != nil && !fsys.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// rangeOf returns one record for every height from..to: the stored one, or
// a gap record for a height the store does not hold.
func (s *store) rangeOf(from, to *big.Int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := map[string]Record{}
	one := big.NewInt(1)
	for b := bucketOf(from); b.Cmp(bucketOf(to)) <= 0; b = new(big.Int).Add(b, one) {
		data, err := s.fs.ReadFile(s.file(b))
		if err != nil {
			if fsys.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, l := range bytes.Split(data, []byte{'\n'}) {
			if len(bytes.TrimSpace(l)) == 0 {
				continue
			}
			var r Record
			if err := json.Unmarshal(l, &r); err != nil {
				continue // a torn last line after a crash
			}
			got[r.Height] = r
		}
	}
	out := []Record{}
	for h := new(big.Int).Set(from); h.Cmp(to) <= 0; h = new(big.Int).Add(h, one) {
		r, ok := got[h.String()]
		if !ok {
			r = Record{Height: h.String(), Gap: true}
		}
		out = append(out, r)
	}
	return out, nil
}
