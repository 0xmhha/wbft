package node

import (
	"sync"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/types"
)

// headPaths keeps the path of the most recent head notifications
// (wbft_headerCopy), at most cap of them, the oldest dropped first.
type headPaths struct {
	mu    sync.Mutex
	cap   int
	m     map[types.Hash]app.HeadPath
	order []types.Hash
}

func newHeadPaths(capacity int) *headPaths {
	return &headPaths{cap: capacity, m: map[types.Hash]app.HeadPath{}}
}

func (p *headPaths) put(h types.Hash, path app.HeadPath) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.m[h]; !ok {
		p.order = append(p.order, h)
		if len(p.order) > p.cap {
			delete(p.m, p.order[0])
			p.order = p.order[1:]
		}
	}
	p.m[h] = path
}

func (p *headPaths) get(h types.Hash) (app.HeadPath, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path, ok := p.m[h]
	return path, ok
}
