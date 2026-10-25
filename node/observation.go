package node

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// ObservationConfig explicitly selects observation-only recent retention.
// All values are required. It supplies no production H or activation height.
// The initial runtime requires the functional journal to be disabled.
type ObservationConfig struct {
	Policy               window.Config
	Retention            types.Height
	HistoryWalk          uint64
	ReplayHeaders        uint64
	WitnessItems         uint32
	WitnessBytes         uint64
	WitnessChecksPerStep uint32
}

type observationRuntime struct {
	mu             sync.Mutex
	cfg            ObservationConfig
	engine         *window.Engine
	chain          types.ChainReader
	rules          *types.Config
	fs             fsys.FS
	dir            string
	state          *window.State
	anchor         types.Hash
	unavailable    error
	witnesses      []observationWitness
	witnessCursor  uint64
	witnessDropped uint64
	witnessError   string
}

type observationChain struct {
	types.ChainReader
	parents []*types.Header
}

func (c observationChain) HeaderByHash(hash types.Hash) *types.Header {
	for i := len(c.parents) - 1; i >= 0; i-- {
		h := c.parents[i]
		if h != nil && codec.BlockHash(h) == hash {
			return h
		}
	}
	return c.ChainReader.HeaderByHash(hash)
}
func (c observationChain) Header(hash types.Hash, index uint64) *types.Header {
	h := c.HeaderByHash(hash)
	if h != nil && h.Number.CmpUint64(index) == 0 {
		return h
	}
	return nil
}
func (c observationChain) HasBlock(hash types.Hash, index uint64) bool {
	return c.Header(hash, index) != nil
}

func freezeObservation(cfg *Config) error {
	if cfg.Observation == nil {
		return nil
	}
	copy := *cfg.Observation
	if !cfg.Journal.Disabled || copy.HistoryWalk == 0 || copy.ReplayHeaders == 0 || copy.WitnessItems == 0 || copy.WitnessBytes == 0 || copy.WitnessBytes >= 1<<63-1 || copy.WitnessChecksPerStep == 0 {
		return fmt.Errorf("%w: observation requires explicit replay limits and a disabled functional journal", ErrConfig)
	}
	_, err := window.NewRecent(copy.Policy, copy.Retention)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	copy.Policy.ChainID = new(big.Int).Set(copy.Policy.ChainID)
	copy.Retention = types.MustHeightFromBig(copy.Retention.Big())
	cfg.Observation = &copy
	return nil
}

func (n *Node) openObservation(cfg *types.Config, genesis types.Hash) (*observationRuntime, error) {
	dir := filepath.Join(n.cfg.DataDir, "observation")
	policyPath := filepath.Join(dir, "policy")
	previous, err := observationRead(n.fs, policyPath, 32)
	if err != nil && !fsys.IsNotExist(err) {
		return nil, err
	}
	if n.cfg.Observation == nil {
		for _, name := range []string{"state.rlp", "witness.rlp"} {
			if _, checkErr := n.fs.Size(filepath.Join(dir, name)); checkErr == nil {
				return nil, refuse("observation configuration is required for persisted observation data")
			} else if !fsys.IsNotExist(checkErr) {
				return nil, checkErr
			}
		}
		if err == nil {
			return nil, refuse("observation policy is required for this data directory")
		}
		return nil, nil
	}
	option := *n.cfg.Observation
	if option.Policy.GenesisHash != genesis || cfg.ChainID == nil || option.Policy.ChainID.Cmp(cfg.ChainID) != 0 {
		return nil, refuse("observation chain identity differs from application")
	}
	engine, err := window.NewRecent(option.Policy, option.Retention)
	if err != nil {
		return nil, err
	}
	digest := engine.Digest()
	if previous != nil && !bytes.Equal(previous, digest[:]) {
		return nil, refuse("observation policy differs from persisted policy")
	}
	r := &observationRuntime{cfg: option, engine: engine, chain: n.d.App, rules: cfg, fs: n.fs, dir: dir}
	if err := r.recover(); err != nil {
		return nil, fmt.Errorf("node: observation recovery: %w", err)
	}
	if err := r.loadWitnesses(); err != nil {
		return nil, fmt.Errorf("node: observation witnesses: %w", err)
	}
	if err := n.fs.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if previous == nil {
		if err := observationWrite(n.fs, policyPath, digest[:]); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func observationRead(fs fsys.FS, path string, limit uint64) ([]byte, error) {
	file, err := fs.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > limit {
		return nil, window.ErrCapacity
	}
	return data, nil
}
func observationWrite(fs fsys.FS, path string, data []byte) error {
	temp := path + ".tmp"
	f, err := fs.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = fs.Remove(temp) }()
	count, err := f.Write(data)
	if err == nil && count != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = fs.Rename(temp, path); err != nil {
		return err
	}
	return fs.SyncDir(filepath.Dir(path))
}

func (r *observationRuntime) history(chain types.ChainReader) (*window.BranchHistory, error) {
	return window.NewBranchHistory(r.engine, chain, r.rules, r.cfg.HistoryWalk)
}
func (r *observationRuntime) CheckFormat(h *types.Header, parents []*types.Header) error {
	if h == nil {
		return window.ErrHistory
	}
	if h.Number.IsZero() && h.ParentHash == (types.Hash{}) {
		_, err := codec.DecodeExtra(h)
		return err
	}
	chain := observationChain{r.chain, parents}
	p := chain.HeaderByHash(h.ParentHash)
	if p == nil {
		return window.ErrHistory
	}
	at := p.Number.AddUint64(1)
	if at.Cmp(r.cfg.Policy.Activation) < 0 {
		_, err := codec.DecodeExtra(h)
		return err
	}
	if h.Number.Cmp(at) != 0 {
		return window.ErrHistory
	}
	x, err := wire.Decode(h.Extra, r.cfg.Policy.Codec)
	if err != nil {
		return err
	}
	if x.Observation.Version != 2 || x.Observation.PolicyDigest != r.engine.Digest() {
		return window.ErrPolicy
	}
	return nil
}

// stateAt derives a detached parent state using hash-bound ancestry only.
// The caller serializes it with canonical adoption and checkpoint recovery.
func (r *observationRuntime) stateAt(parent *types.Header, chain types.ChainReader) (*window.State, error) {
	if parent == nil {
		return nil, window.ErrHistory
	}
	if r.unavailable != nil {
		return nil, r.unavailable
	}
	var suffix []*types.Header
	current := parent
	var state *window.State
	for {
		hash := codec.BlockHash(current)
		if r.state != nil && hash == r.anchor {
			state = r.state
			break
		}
		if current.Number.AddUint64(1).Cmp(r.cfg.Policy.Activation) == 0 {
			var err error
			state, err = r.engine.Initial(current)
			if err != nil {
				return nil, err
			}
			break
		}
		if current.Number.Cmp(r.cfg.Policy.Activation) < 0 || uint64(len(suffix)) >= r.cfg.ReplayHeaders {
			return nil, window.ErrHistory
		}
		suffix = append(suffix, current)
		previous := chain.HeaderByHash(current.ParentHash)
		if previous == nil || previous.Number.AddUint64(1).Cmp(current.Number) != 0 || codec.BlockHash(previous) != current.ParentHash {
			return nil, window.ErrHistory
		}
		current = previous
	}
	history, err := r.history(chain)
	if err != nil {
		return nil, err
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		state, err = r.engine.VerifyAndApply(state, suffix[i], history)
		if err != nil {
			return nil, err
		}
	}
	return state, nil
}
func (r *observationRuntime) VerifyObservation(h *types.Header, parents []*types.Header) error {
	if h.Number.Cmp(r.cfg.Policy.Activation) < 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	chain := observationChain{r.chain, parents}
	state, err := r.stateAt(chain.HeaderByHash(h.ParentHash), chain)
	if err != nil {
		return err
	}
	history, err := r.history(chain)
	if err != nil {
		return err
	}
	_, err = r.engine.Apply(state, h, history)
	return err
}

func (r *observationRuntime) recover() error {
	head := r.chain.Head()
	if head == nil {
		return window.ErrHistory
	}
	raw, err := observationRead(r.fs, filepath.Join(r.dir, "state.rlp"), r.engine.CheckpointLimit())
	if err != nil && !fsys.IsNotExist(err) {
		return err
	}
	if err == nil {
		// File metadata is only a lookup hint. The application head's ancestry
		// supplies the independent trust anchor before Recover verifies the state.
		var hint struct {
			Version uint64
			Height  *big.Int
			Hash    types.Hash
			State   rlp.RawValue
		}
		if err := rlp.DecodeStrict(raw, &hint); err != nil || hint.Height == nil {
			return window.ErrState
		}
		current := head
		for walked := uint64(0); ; walked++ {
			if codec.BlockHash(current) == hint.Hash && current.Number.Big().Cmp(hint.Height) == 0 {
				break
			}
			if walked >= r.cfg.ReplayHeaders || current.Number.Cmp(r.cfg.Policy.Activation) <= 0 {
				return window.ErrHistory
			}
			previous := r.chain.HeaderByHash(current.ParentHash)
			if previous == nil || previous.Number.AddUint64(1).Cmp(current.Number) != 0 || codec.BlockHash(previous) != current.ParentHash {
				return window.ErrHistory
			}
			current = previous
		}
		r.state, err = r.engine.Recover(raw, current)
		if err != nil {
			return err
		}
		r.anchor = hint.Hash
	}
	if head.Number.Cmp(r.cfg.Policy.Activation) < 0 {
		return nil
	}
	state, err := r.stateAt(head, r.chain)
	if err != nil {
		return err
	}
	r.state = state
	r.anchor = codec.BlockHash(head)
	return nil
}

func (r *observationRuntime) adopt(h *types.Header) error {
	if h.Number.Cmp(r.cfg.Policy.Activation) < 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.stateAt(h, r.chain)
	if err == nil {
		var raw []byte
		raw, err = r.engine.EncodeCheckpoint(state, h)
		if err == nil {
			err = observationWrite(r.fs, filepath.Join(r.dir, "state.rlp"), raw)
		}
	}
	if err != nil {
		r.unavailable = err
		return err
	}
	r.state = state
	r.anchor = codec.BlockHash(h)
	return nil
}

func (s *service) PrepareObservation(_ context.Context, h *types.Header) (*types.Header, error) {
	view, _, err := s.ready()
	if err != nil {
		return nil, err
	}
	r := view.observation
	if r == nil || h.Number.Cmp(r.cfg.Policy.Activation) < 0 {
		return h, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	parent := r.chain.HeaderByHash(h.ParentHash)
	state, err := r.stateAt(parent, r.chain)
	if err != nil {
		return nil, err
	}
	history, err := r.history(r.chain)
	if err != nil {
		return nil, err
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return nil, err
	}
	proofs, err := r.selectProofs(h, x, history)
	if err != nil {
		return nil, err
	}
	carrier, _, err := r.engine.Build(state, h, proofs, history)
	return carrier, err
}

func (r *observationRuntime) info() *rpc.ObservationInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := &rpc.ObservationInfo{PolicyDigest: r.engine.Digest(), Activation: r.cfg.Policy.Activation.String(), Retention: r.cfg.Retention.String(), Window: r.cfg.Policy.Window, Status: "BEFORE_ACTIVATION"}
	result.WitnessItems = uint32(len(r.witnesses))
	result.WitnessDropped = r.witnessDropped
	result.WitnessError = r.witnessError
	if r.unavailable != nil {
		result.Status = "UNAVAILABLE"
		result.Error = r.unavailable.Error()
		return result
	}
	if r.state == nil {
		return result
	}
	result.Status = "AVAILABLE"
	from, through, _ := r.state.RecentWindow()
	result.MaturedFrom = from.String()
	result.MaturedThrough = through.String()
	from, through, _ = r.state.SettledWindow()
	result.SettledFrom = from.String()
	result.SettledThrough = through.String()
	return result
}
