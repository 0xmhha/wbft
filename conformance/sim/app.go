package sim

import (
	"encoding/hex"
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
	"github.com/0xmhha/wbft/observe/event"
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
	serial  *serialBuilder
	sealing *sealingBuilder
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
	switch n.spec.BuildQueuePolicy {
	case BuildQueueSerial:
		a.serial = newSerialBuilder(a)
	case BuildQueueSealing:
		a.sealing = newSealingBuilder(a)
	}
	a.snapshot(n.s.genesis.Header)
	return a
}

func (a *app) snapshot(h *types.Header) {
	var candidates []types.CandidateEntry
	if a.n.cfg.Rules(types.EpochInfoInProposal, h.Number.AddUint64(1)) {
		candidates = a.n.s.candidates(index(h))
	}
	s, err := source.NewAuthoritySnapshot(h.Number, codec.BlockHash(h), uint256.NewInt(types.InitialGasTip), nil, nil, candidates)
	if err == nil {
		a.snaps[codec.BlockHash(h)] = s
	}
}

// dropPending forgets imports in flight (a crash or a stop).
func (a *app) dropPending() {
	a.gen++
	if a.sealing != nil {
		a.sealing.kill()
	}
	if a.serial != nil {
		a.serial.crash()
	}
}
func (a *app) stopPending() {
	a.gen++
	if a.sealing != nil {
		a.sealing.close()
	}
	if a.serial != nil {
		a.serial.stop()
	}
}

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
	return &header.Env{Config: a.n.cfg, Chain: a.chain, BadBlock: a.IsBadBlock, PartB: partB{a}, Snapshots: a, Now: a.n.clock.Now,
		UseFutureTimeAllowance: a.n.spec.Options.Improvements.Has(consensus.UseFutureTimeAllowance)}
}

// Head implements runner.Chain.
func (a *app) Head() *types.Header { return a.chain.head.Header }

// ValidatorsAt implements runner.Chain.
func (a *app) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(a.chain, a.n.cfg, n, parent, nil)
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
	if a.sealing != nil {
		a.sealing.offer(req, wait)
		return
	}
	if a.serial != nil {
		a.serial.offer(req, wait, done)
		return
	}
	s := a.n.s
	samples := s.sc.App.BuildDelay
	if len(a.n.spec.BuildDelay) > 0 {
		samples = a.n.spec.BuildDelay
	}
	delay := wait + sample(s.rng, samples)
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
	if isEpoch, err := validator.IsEpochBlock(a.n.cfg, n); err == nil && isEpoch {
		at := index(h)
		if a.n.cfg.Rules(types.EpochInfoInProposal, n) {
			at = index(head)
		}
		ei, err := epoch.ComputeNextEpochInfo(a.chain, a.n.cfg, h, s.candidates(at))
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
func (a *app) FinalizeBlock(b *types.Block, _ types.Round) error { return a.finalizeImport(b) }
func (a *app) importDelay(b *types.Block) time.Duration {
	s := a.n.s
	samples := s.sc.App.ImportDelay
	if len(a.n.spec.ImportDelay) > 0 {
		samples = a.n.spec.ImportDelay
	}
	d := sample(s.rng, samples)
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
	return d
}
func (a *app) finalizeImport(b *types.Block) error {
	return a.scheduleImport(b, event.PathSealedLocally)
}
func (a *app) scheduleImport(b *types.Block, path string) error {
	d := a.importDelay(b)
	gen := a.gen
	a.n.clock.AfterFunc(d, func() {
		if gen != a.gen {
			return
		}
		_ = a.importBlock(b, path)
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
		if a.n.r != nil && a.n.alive {
			// What a node records for an application's OnImportFailed.
			_ = a.n.ev.Write(event.Record{Kind: event.ImportFail, Fields: map[string]any{"number": b.Header.Number.String(),
				"hash": "0x" + hex.EncodeToString(codec.BlockHash(b.Header).Bytes()), "path": path, "recorded_bad": true}}, a.n.stamp())
		}
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
	// Every distinct sealed header is verified once per configuration: the header
	// rules and the light verification (both check the seals).
	enc, err := codec.EncodeHeader(b.Header)
	if err != nil {
		return err
	}
	key := verificationKey{Header: keccak.Sum256(enc, codec.BlockHash(a.chain.head.Header).Bytes()), Config: a.n.cfgHash,
		FutureTimeAllowance: a.n.spec.Options.Improvements.Has(consensus.UseFutureTimeAllowance)}
	if !s.verified[key] {
		env := a.env()
		env.PartB = nil
		if err := header.VerifyHeader(env, b.Header, nil, header.Options{CheckSeals: true, Mode: header.HeaderOnly}); err != nil {
			s.violate("header", a.n.v.address, "block %d: %v", h, err)
			return err
		}
		if r, err := header.VerifyLight(header.LightInputs{Config: a.n.cfg, Trusted: trusted{a}}, b.Header, a.chain.head.Header); r != header.Valid {
			snapshot, known := a.Get(b.Header.ParentHash)
			if r != header.CannotDecide || !errors.Is(err, header.ErrLightEpochState) || !known || snapshot == nil || !snapshot.HasCandidates() {
				s.violate("header", a.n.v.address, "block %d light verification %s: %v", h, r, err)
				return fmt.Errorf("light verification %s", r)
			}
			// The state-bound check above succeeded with known candidates.
			// Preserve the light verifier's partial verdict separately.
			s.lightChecks = append(s.lightChecks, LightCheck{Node: a.n.v.address, Number: b.Header.Number.String(), Hash: codec.BlockHash(b.Header), Verdict: r.String(), Reason: err.Error(), FullStateVerified: true})
		}
		s.verified[key] = true
	}
	a.chain.insert(b)
	a.snapshot(b.Header)
	s.noteDecided(a.n, b)
	delete(a.pending, h)
	if a.n.r != nil && a.n.alive {
		_ = a.n.ev.Write(eventNewHead(b, path), a.n.stamp())
		if a.sealing == nil {
			a.n.r.NewHead(b.Header)
		}
	}
	if a.sealing != nil {
		a.sealing.headNotice(b.Header)
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
	return validator.ValidatorsAt(t.a.chain, t.a.n.cfg, n, parent, nil)
}

func (a *app) head() uint64 { return index(a.chain.head.Header) }

func sample(r interface{ IntN(int) int }, ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[r.IntN(len(ds))]
}
