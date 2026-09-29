package sim

import (
	"errors"
	"fmt"
	"time"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// poison is the transaction that makes a block fail execution.
var poison = []byte("wbft-sim-poison")

// errPoison is the execution failure of a poisoned block.
var errPoison = errors.New("sim: block execution failed")

// importFail is the transaction that makes a block fail import after it
// passed proposal validation.
var importFail = []byte("wbft-sim-import-fail")

// errImportFail is the import failure of a block carrying importFail.
var errImportFail = errors.New("sim: block import failed")

// hasTx reports whether the transaction list of body holds tx.
func hasTx(body types.BodyRaw, tx []byte) bool {
	if len(body) == 0 {
		return false
	}
	items, err := rlp.ListItems(body[0])
	if err != nil {
		return false
	}
	for _, it := range items {
		var b []byte
		if rlp.DecodeStrict(it, &b) == nil && string(b) == string(tx) {
			return true
		}
	}
	return false
}

// app is the fake application of a node: a key-value-free chain whose
// headers are real WBFT headers (block hash, seals, EpochInfo and randao
// are real). Its chain is durable: an imported block survives a crash.
type app struct {
	n       *node
	chain   *memChain
	snaps   map[types.Hash]*source.AuthoritySnapshot
	bad     map[types.Hash]bool
	pending map[uint64]*types.Block
	gen     int // import generation; pending imports of an earlier one are dropped
}

func newApp(n *node) *app {
	a := &app{n: n, chain: newMemChain(n.s.genesis), snaps: map[types.Hash]*source.AuthoritySnapshot{},
		bad: map[types.Hash]bool{}, pending: map[uint64]*types.Block{}}
	a.snapshot(n.s.genesis.Header)
	return a
}

func (a *app) snapshot(h *types.Header) {
	s, err := source.NewAuthoritySnapshot(h.Number, codec.BlockHash(h), uint256.NewInt(types.InitialGasTip), nil, nil, nil)
	if err == nil {
		a.snaps[codec.BlockHash(h)] = s
	}
}

// dropPending forgets imports in flight (a crash or a stop).
func (a *app) dropPending() { a.gen++ }

func (a *app) Get(h types.Hash) (*source.AuthoritySnapshot, bool) {
	s, ok := a.snaps[h]
	return s, ok
}

// partB is the execution side of proposal verification: a poisoned block
// fails step P4.
type partB struct{ a *app }

func (p partB) VerifyPartB(step string, _ *types.Header, _ *types.Header, body types.BodyRaw) error {
	if step == "P4" && hasTx(body, poison) {
		return errPoison
	}
	return nil
}

func (a *app) env() *header.Env {
	return &header.Env{Config: a.n.s.cfg, Chain: a.chain, BadBlock: a.IsBadBlock, PartB: partB{a}, Snapshots: a, Now: a.n.clock.Now}
}

// Head implements runner.Chain.
func (a *app) Head() *types.Header { return a.chain.head.Header }

// ValidatorsAt implements runner.Chain.
func (a *app) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(a.chain, a.n.s.cfg, n, parent, nil)
}

// ValidateProposal implements runner.Chain. A block that fails execution is
// recorded as bad.
func (a *app) ValidateProposal(b *types.Block) (time.Duration, error) {
	d, err := header.VerifyProposal(a.env(), b)
	if errors.Is(err, errPoison) {
		a.bad[codec.BlockHash(b.Header)] = true
	}
	return d, err
}

// IsBadBlock implements runner.Chain.
func (a *app) IsBadBlock(h types.Hash) bool { return a.bad[h] }

// randao signs the randao data with the node's signer.
type randao struct {
	n      *node
	number types.Height
}

func (r randao) SignRandao([]byte) ([]byte, error) {
	if r.n.r == nil {
		return nil, fmt.Errorf("sim: node is down")
	}
	return r.n.signerRandao(r.number)
}

// ReadyToBuild implements runner.App: after the wait and the build time the
// builder assembles a block on the current head and submits it.
func (a *app) ReadyToBuild(req consensus.RequestBuild, wait time.Duration, done <-chan struct{}) {
	s := a.n.s
	delay := wait + sample(s.rng, s.sc.App.BuildDelay)
	gen := a.gen
	a.n.clock.AfterFunc(delay, func() {
		if gen != a.gen || a.n.r == nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		head := a.chain.head.Header
		if head.Number.AddUint64(1).Cmp(req.Height) != 0 {
			return
		}
		b, err := a.build(head)
		if err != nil {
			// A builder that cannot assemble a block (a node that is not
			// the proposer of an epoch block) proposes nothing, as the
			// reference's builder does.
			return
		}
		a.n.r.Submit(b)
	})
}

// build assembles a block on head.
func (a *app) build(head *types.Header) (*types.Block, error) {
	s := a.n.s
	n := head.Number.AddUint64(1)
	root := keccak.Sum256(head.Root[:], n.Bytes())
	skel := &types.Header{ParentHash: codec.BlockHash(head), UncleHash: types.EmptyUncleHash, Number: n, Root: root,
		GasLimit: head.GasLimit, BaseFee: head.BaseFee, Extra: []byte("wbft-sim")}
	ep, ec := a.n.r.Snapshot().ExtraSeals(head)
	h, err := header.PrepareProposal(a.env(), skel, header.ProposalInputs{Coinbase: a.n.v.address, Signer: randao{a.n, n},
		ExtraPrepared: ep, ExtraCommitted: ec, ParentGasTip: uint256.NewInt(types.InitialGasTip)})
	if err != nil {
		return nil, err
	}
	txs := []byte{0xc0}
	for _, bp := range s.sc.App.BadProposals {
		if bp.Proposer == a.n.v.address && n.CmpUint64(bp.Height) == 0 {
			if txs, err = rlp.Encode([][]byte{poison}); err != nil {
				return nil, err
			}
		}
	}
	for _, bp := range s.sc.App.FailedImports {
		if bp.Proposer == a.n.v.address && n.CmpUint64(bp.Height) == 0 {
			if txs, err = rlp.Encode([][]byte{importFail}); err != nil {
				return nil, err
			}
		}
	}
	if isEpoch, err := validator.IsEpochBlock(s.cfg, n); err == nil && isEpoch {
		ei, err := epoch.ComputeNextEpochInfo(a.chain, s.cfg, h, s.candidates(index(h)))
		if err != nil {
			return nil, err
		}
		x, err := codec.DecodeExtra(h)
		if err != nil {
			return nil, err
		}
		x.EpochInfo = ei
		if err := codec.SetExtra(h, x); err != nil {
			return nil, err
		}
	}
	return &types.Block{Header: h, Body: types.BodyRaw{txs, {0xc0}}}, nil
}

// candidates returns the candidate list of the state after epoch block e.
func (s *simulation) candidates(e uint64) []types.CandidateEntry {
	idx := make([]int, 0)
	for i := 0; i < s.sc.Genesis; i++ {
		idx = append(idx, i)
	}
	for _, c := range s.sc.Epochs {
		if c.Block <= e {
			idx = c.Candidates
		}
	}
	out := make([]types.CandidateEntry, 0, len(idx))
	for _, i := range idx {
		v := s.sc.Validators[i]
		out = append(out, types.CandidateEntry{Addr: v.address, BLSPublicKey: v.blsPub})
	}
	return out
}

// FinalizeBlock implements runner.App: the block is imported after the
// import time; the result is not reported back (the core ignores it).
func (a *app) FinalizeBlock(b *types.Block, _ types.Round) error {
	s := a.n.s
	d := sample(s.rng, s.sc.App.ImportDelay)
	for _, x := range s.sc.App.SlowImport {
		if x.Height == index(b.Header) && (x.Node == types.Address{} || x.Node == a.n.v.address) {
			d = x.Delay
		}
	}
	if hasTx(b.Body, importFail) {
		for _, x := range s.sc.App.FailedImports {
			if x.Height == index(b.Header) && x.Proposer == b.Header.Coinbase {
				d = x.Delay
			}
		}
	}
	gen := a.gen
	a.n.clock.AfterFunc(d, func() {
		if gen != a.gen {
			return
		}
		_ = a.importBlock(b, "sealed_locally")
	})
	return nil
}

// importBlock verifies and stores a block that extends the head, notifies
// the runner and announces the block to the peers. A block above head + 1
// waits for its parent; a block at or below the head is compared with the
// stored one.
func (a *app) importBlock(b *types.Block, path string) error {
	s := a.n.s
	h := index(b.Header)
	if hasTx(b.Body, importFail) {
		// The block fails import whenever it is imported, also when a
		// repeated finalize arrives after the height was decided otherwise.
		a.bad[codec.BlockHash(b.Header)] = true
		delete(a.pending, h)
		return errImportFail
	}
	head := a.head()
	switch {
	case h <= head:
		if stored := a.chain.byNum[h]; stored != nil && codec.BlockHash(stored.Header) != codec.BlockHash(b.Header) {
			s.violate("agreement", a.n.v.address, "height %d: received %x, stored %x", h, codec.BlockHash(b.Header).Bytes()[:4], codec.BlockHash(stored.Header).Bytes()[:4])
		}
		return nil
	case h > head+1:
		if _, ok := a.pending[h]; !ok {
			a.pending[h] = b
		}
		return nil
	}
	if b.Header.ParentHash != codec.BlockHash(a.chain.head.Header) {
		return fmt.Errorf("sim: block %d does not extend the head", h)
	}
	// Every distinct sealed header is verified once per run: the header
	// rules and the light verification (both check the seals).
	enc, err := codec.EncodeHeader(b.Header)
	if err != nil {
		return err
	}
	key := keccak.Sum256(enc, codec.BlockHash(a.chain.head.Header).Bytes())
	if !s.verified[key] {
		env := a.env()
		env.PartB = nil
		if err := header.VerifyHeader(env, b.Header, nil, header.Options{CheckSeals: true, Mode: header.HeaderOnly}); err != nil {
			s.violate("header", a.n.v.address, "block %d: %v", h, err)
			return err
		}
		if r, err := header.VerifyLight(header.LightInputs{Config: s.cfg, Trusted: trusted{a}}, b.Header, a.chain.head.Header); r != header.Valid {
			s.violate("header", a.n.v.address, "block %d light verification %s: %v", h, r, err)
			return fmt.Errorf("light verification %s", r)
		}
		s.verified[key] = true
	}
	a.chain.insert(b)
	a.snapshot(b.Header)
	s.noteDecided(a.n, b)
	delete(a.pending, h)
	if a.n.r != nil && a.n.alive {
		_ = a.n.ev.Write(eventNewHead(b, path), a.n.stamp())
		a.n.r.NewHead(b.Header)
	}
	if a.n.alive && a.n.tr != nil {
		a.n.tr.announce(b)
	}
	if next, ok := a.pending[h+1]; ok {
		return a.importBlock(next, "imported")
	}
	return nil
}

type trusted struct{ a *app }

func (t trusted) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(t.a.chain, t.a.n.s.cfg, n, parent, nil)
}

func (a *app) head() uint64 { return index(a.chain.head.Header) }

func sample(r interface{ IntN(int) int }, ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[r.IntN(len(ds))]
}
