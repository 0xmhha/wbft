package kvstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// store keeps the canonical chain in memory and one file per block on
// disk (blocks/<number>.rlp, written atomically). It implements
// types.ChainReader. The chain of this example never exceeds 2^64 blocks,
// so the canonical index is the block number.
type store struct {
	dir string

	mu     sync.RWMutex
	byNum  []*types.Block
	byHash map[types.Hash]*types.Block
}

func blockFile(dir string, n uint64) string {
	return filepath.Join(dir, "blocks", fmt.Sprintf("%012d.rlp", n))
}

// openStore loads the blocks of dir; an empty directory gets genesis.
func openStore(dir string, genesis *types.Block) (*store, error) {
	s := &store{dir: dir, byHash: map[types.Hash]*types.Block{}}
	if err := os.MkdirAll(filepath.Join(dir, "blocks"), 0o700); err != nil {
		return nil, err
	}
	for n := uint64(0); ; n++ {
		raw, err := os.ReadFile(blockFile(dir, n))
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return nil, err
		}
		b, err := codec.DecodeBlock(raw)
		if err != nil {
			return nil, fmt.Errorf("kvstore: block %d: %w", n, err)
		}
		s.byNum = append(s.byNum, b)
		s.byHash[codec.BlockHash(b.Header)] = b
	}
	if len(s.byNum) == 0 {
		if err := s.append(genesis); err != nil {
			return nil, err
		}
	} else if codec.BlockHash(s.byNum[0].Header) != codec.BlockHash(genesis.Header) {
		return nil, fmt.Errorf("kvstore: the stored chain has another genesis")
	}
	return s, nil
}

// append stores a block that extends the head, durably.
func (s *store) append(b *types.Block) error {
	raw, err := codec.EncodeBlock(b)
	if err != nil {
		return err
	}
	n := uint64(len(s.blocks()))
	name := blockFile(s.dir, n)
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(name)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	s.mu.Lock()
	s.byNum = append(s.byNum, b)
	s.byHash[codec.BlockHash(b.Header)] = b
	s.mu.Unlock()
	return nil
}

func (s *store) blocks() []*types.Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byNum
}

func (s *store) head() *types.Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byNum[len(s.byNum)-1]
}

func (s *store) blockByNumber(n uint64) *types.Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n >= uint64(len(s.byNum)) {
		return nil
	}
	return s.byNum[n]
}

func (s *store) Head() *types.Header { return s.head().Header }

func (s *store) HeaderByNumber(idx uint64) *types.Header {
	if b := s.blockByNumber(idx); b != nil {
		return b.Header
	}
	return nil
}

func (s *store) Header(hash types.Hash, idx uint64) *types.Header {
	if h := s.HeaderByHash(hash); h != nil && h.Number.CmpUint64(idx) == 0 {
		return h
	}
	return nil
}

func (s *store) HeaderByHash(hash types.Hash) *types.Header {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b := s.byHash[hash]; b != nil {
		return b.Header
	}
	return nil
}

func (s *store) HasBlock(hash types.Hash, idx uint64) bool { return s.Header(hash, idx) != nil }
