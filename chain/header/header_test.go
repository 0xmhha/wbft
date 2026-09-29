package header

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/chain/validator/source"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
)

// ---------------------------------------------------------------- fixture

type account struct {
	key  *ecdsa.PrivateKey
	addr types.Address
	bls  *bls.SecretKey
}

func accounts(t testing.TB, n int) []account {
	t.Helper()
	out := make([]account, n)
	for i := range out {
		k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("wbft-spec-vector-key-" + strconv.Itoa(i))))
		if err != nil {
			t.Fatal(err)
		}
		sk, err := bls.DeriveSecretKey(ecdsa.PrivateKeyBytes(k))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = account{key: k, addr: ecdsa.Address(k), bls: sk}
	}
	return out
}

type memChain struct {
	byHash map[types.Hash]*types.Header
	byNum  map[uint64]*types.Header
}

func newMemChain() *memChain {
	return &memChain{byHash: map[types.Hash]*types.Header{}, byNum: map[uint64]*types.Header{}}
}

func (c *memChain) add(h *types.Header) {
	c.byHash[codec.BlockHash(h)] = h
	c.byNum[h.Number.RefLow64()] = h
}
func (c *memChain) Head() *types.Header                     { return nil }
func (c *memChain) HeaderByNumber(i uint64) *types.Header   { return c.byNum[i] }
func (c *memChain) HeaderByHash(h types.Hash) *types.Header { return c.byHash[h] }
func (c *memChain) HasBlock(h types.Hash, i uint64) bool    { return c.Header(h, i) != nil }
func (c *memChain) Header(h types.Hash, i uint64) *types.Header {
	x := c.byHash[h]
	if x == nil || x.Number.RefLow64() != i {
		return nil
	}
	return x
}

type keySigner struct{ k *ecdsa.PrivateKey }

func (s keySigner) SignRandao(d []byte) ([]byte, error) { return ecdsa.SignData(d, s.k) }

const t0 = 1_700_000_000

// builder makes a valid chain: genesis validators 0..3, epoch length 4,
// block 4 records validators [3, 1, 0, 2] of candidates 0..3.
type builder struct {
	t     *testing.T
	acc   []account
	cfg   *types.Config
	chain *memChain
	hs    []*types.Header
	tip   *uint256.Int
}

func newBuilder(t *testing.T) *builder {
	acc := accounts(t, 6)
	pol := uint64(0)
	init := types.GenesisInit{}
	for _, a := range acc[:4] {
		init.Validators = append(init.Validators, a.addr)
		init.BLSPublicKeys = append(init.BLSPublicKeys, a.bls.PublicKey().Bytes())
	}
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: &pol},
		nil, init, big.NewInt(8282))
	ei, err := epoch.InitialEpochInfo(init)
	if err != nil {
		t.Fatal(err)
	}
	g := &types.Header{
		UncleHash: types.EmptyUncleHash, Root: keccak.Sum256([]byte("root0")), Difficulty: big.NewInt(1),
		Number: types.HeightFromUint64(0), GasLimit: 105_000_000, Time: t0, BaseFee: big.NewInt(20_000_000_000_000),
	}
	if err := codec.SetExtra(g, &types.WBFTExtra{GasTip: new(big.Int).SetUint64(types.InitialGasTip), EpochInfo: ei}); err != nil {
		t.Fatal(err)
	}
	b := &builder{t: t, acc: acc, cfg: cfg, chain: newMemChain(), hs: []*types.Header{g}, tip: uint256.NewInt(types.InitialGasTip)}
	b.chain.add(g)
	return b
}

func (b *builder) env(now uint64) *Env {
	return &Env{Config: b.cfg, Chain: b.chain, Now: func() time.Time { return time.Unix(int64(now), 0) }}
}

func (b *builder) head() *types.Header { return b.hs[len(b.hs)-1] }

// propose builds the next header with account key on top of the head.
func (b *builder) propose(key int, extraP, extraC []types.SealEntry) *types.Header {
	t := b.t
	parent := b.head()
	n := parent.Number.AddUint64(1)
	sk := &types.Header{ParentHash: codec.BlockHash(parent), UncleHash: types.EmptyUncleHash, Number: n,
		Root: keccak.Sum256(n.Bytes()), GasLimit: parent.GasLimit, BaseFee: parent.BaseFee}
	h, err := PrepareProposal(b.env(parent.Time), sk, ProposalInputs{
		Coinbase: b.acc[key].addr, Signer: keySigner{b.acc[key].key},
		ExtraPrepared: extraP, ExtraCommitted: extraC, ParentGasTip: b.tip,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (b *builder) set(h *types.Header, parents []*types.Header) *validator.Set {
	vs, err := validator.ValidatorsAt(b.chain, b.cfg, h.Number, h.ParentHash, parents)
	if err != nil {
		b.t.Fatal(err)
	}
	return vs
}

func (b *builder) seals(h *types.Header, round uint32, st types.SealType, idx []int) []types.SealEntry {
	vs := b.set(h, nil)
	var out []types.SealEntry
	for _, i := range idx {
		m := vs.At(i)
		var sk *bls.SecretKey
		for _, a := range b.acc {
			if a.addr == m.Addr {
				sk = a.bls
			}
		}
		out = append(out, types.SealEntry{Sealer: uint32(i), Seal: sk.Sign(codec.SealData(h, round, st)).Bytes()})
	}
	return out
}

// seal writes the seals of the given indices with CommitHeader.
func (b *builder) seal(h *types.Header, round uint32, idx []int) *types.Header {
	blk, err := CommitHeader(&types.Block{Header: h}, types.RoundFromUint64(uint64(round)),
		b.seals(h, round, types.PrepareSeal, idx), b.seals(h, round, types.CommitSeal, idx))
	if err != nil {
		b.t.Fatal(err)
	}
	return blk.Header
}

func (b *builder) store(h *types.Header) {
	b.chain.add(h)
	b.hs = append(b.hs, h)
}

func (b *builder) setEpochInfo(h *types.Header, ei *types.EpochInfo) {
	x, err := codec.DecodeExtra(h)
	if err != nil {
		b.t.Fatal(err)
	}
	x.EpochInfo = ei
	if err := codec.SetExtra(h, x); err != nil {
		b.t.Fatal(err)
	}
}

// build makes blocks 1..n.
func (b *builder) build(n int) {
	plan := []struct {
		key   int
		round uint32
		idx   []int
	}{{0, 0, []int{0, 1, 2}}, {1, 1, []int{0, 1, 2, 3}}, {2, 0, []int{1, 2, 3}}, {3, 0, []int{0, 1, 2}},
		{3, 0, []int{0, 1, 2}}, {1, 0, []int{0, 1, 2, 3}}, {0, 0, []int{1, 2, 3}}}
	for i := 0; i < n; i++ {
		p := plan[i]
		h := b.propose(p.key, nil, nil)
		if i+1 == 4 {
			ei := &types.EpochInfo{}
			for j, a := range b.acc[:4] {
				ei.Candidates = append(ei.Candidates, types.Candidate{Addr: a.addr, Diligence: types.DefaultDiligence})
				_ = j
			}
			for _, v := range []uint32{3, 1, 0, 2} {
				ei.Validators = append(ei.Validators, v)
				ei.BLSPublicKeys = append(ei.BLSPublicKeys, b.acc[v].bls.PublicKey().Bytes())
			}
			b.setEpochInfo(h, ei)
		}
		b.store(b.seal(h, p.round, p.idx))
	}
}

var headerOnly = Options{CheckSeals: true, Mode: HeaderOnly}

func stepOf(err error) string {
	var se *StepError
	if errors.As(err, &se) {
		return se.Step
	}
	return ""
}

// ---------------------------------------------------------------- tests

func TestBuiltChainVerifies(t *testing.T) {
	b := newBuilder(t)
	b.build(7)
	now := uint64(t0 + 100)
	for i, h := range b.hs {
		if err := VerifyHeader(b.env(now), h, nil, headerOnly); err != nil {
			t.Errorf("block %d: %v", i, err)
		}
	}
	// V and Vp differ across the epoch boundary.
	v5 := b.set(b.hs[5], nil)
	if v5.At(0).Addr != b.acc[3].addr {
		t.Error("validator set of block 5 does not come from block 4")
	}
	// The whole chain as one batch on a store holding only the genesis.
	g := newBuilder(t)
	env := &Env{Config: b.cfg, Chain: g.chain, Now: b.env(now).Now}
	for i, err := range VerifyHeaderBatch(env, b.hs[1:], headerOnly) {
		if err != nil {
			t.Errorf("batch header %d: %v", i+1, err)
		}
	}
}

// Every step of header verification in order, and vanity data of any length
// or content is accepted.
//
// Covers: WBFT-HDR-017, WBFT-PARAM-012
func TestVerifyHeaderFirstFailingStep(t *testing.T) {
	b := newBuilder(t)
	b.build(6)
	now := uint64(t0 + 100)
	parent := b.hs[6]
	// next returns block 7 proposed by key 1 (a member of V(7)) after mut,
	// sealed by indices 0, 1, 2 unless unsealed.
	next := func(key int, mut func(h *types.Header), post func(h *types.Header)) *types.Header {
		h := b.propose(key, nil, nil)
		if mut != nil {
			mut(h)
		}
		h = b.seal(h, 0, []int{0, 1, 2})
		if post != nil {
			post(h)
		}
		return h
	}
	setX := func(h *types.Header, f func(x *types.WBFTExtra)) {
		x, err := codec.DecodeExtra(h)
		if err != nil {
			t.Fatal(err)
		}
		f(x)
		if err := codec.SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
	}
	resign := func(h *types.Header, key int, number uint64) {
		rev, _ := ecdsa.SignData(codec.RandaoData(big.NewInt(8282), types.HeightFromUint64(number)), b.acc[key].key)
		setX(h, func(x *types.WBFTExtra) { x.RandaoReveal = rev })
		h.MixDigest = RandaoMix(parent.MixDigest, rev)
	}
	tests := []struct {
		name string
		h    *types.Header
		now  uint64
		step string
		want error
	}{
		{"valid", next(1, nil, nil), now, "", nil},
		{"empty vanity", next(1, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.VanityData = nil }) }, nil), now, "", nil},
		{"short vanity", next(1, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.VanityData = []byte("wbft") }) }, nil), now, "", nil},
		{"long vanity", next(1, func(h *types.Header) {
			setX(h, func(x *types.WBFTExtra) { x.VanityData = bytes.Repeat([]byte{0xff}, 40) })
		}, nil), now, "", nil},
		{"future", next(1, func(h *types.Header) { h.Time = now + 10 }, nil), now, "H2", ErrFutureBlock},
		{"future and bad difficulty", next(1, func(h *types.Header) { h.Time = now + 10; h.Difficulty = big.NewInt(2) }, nil), now, "H2", ErrFutureBlock},
		{"difficulty", next(1, func(h *types.Header) { h.Difficulty = big.NewInt(0) }, nil), now, "H4", ErrInvalidDifficulty},
		{"unknown parent", next(1, nil, func(h *types.Header) { h.ParentHash = types.Hash{1} }), now, "V0b", ErrUnknownAncestor},
		{"parent number", next(1, nil, func(h *types.Header) { h.ParentHash = codec.BlockHash(b.hs[5]) }), now, "V0b", ErrUnknownAncestor},
		{"timestamp", next(1, func(h *types.Header) { h.Time = parent.Time }, nil), now, "H12", ErrInvalidTimestamp},
		{"coinbase", next(5, nil, nil), now, "H15a", ErrUnauthorized},
		{"extra", next(1, nil, func(h *types.Header) { h.Extra = append(h.Extra, 0) }), now, "H16", ErrInvalidExtraDataFormat},
		{"prepared absent", next(1, nil, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.PreparedSeal = nil }) }), now, "H17", ErrEmptyPreparedSeals},
		{"committed empty", next(1, nil, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.CommittedSeal.Signature = nil }) }), now, "H17", ErrEmptyCommittedSeals},
		{"prepared wrong round", next(1, nil, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.Round = 1 }) }), now, "H17", ErrInvalidPreparedSeals},
		{"sealer out of range", next(1, nil, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.PreparedSeal.Sealers.SetSealer(4) }) }), now, "H17", ErrInvalidPreparedSeals},
		{"randao signer", next(1, func(h *types.Header) { resign(h, 2, 7) }, nil), now, "H18", ErrInvalidRandaoReveal},
		{"randao number", next(1, func(h *types.Header) { resign(h, 1, 6) }, nil), now, "H18", ErrInvalidRandaoReveal},
		{"mix", next(1, func(h *types.Header) { h.MixDigest[31] ^= 1 }, nil), now, "H19", ErrInvalidRandaoMix},
		{"prev round", next(1, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.PrevRound = 1 }) }, nil), now, "H20", ErrInvalidPrevPreparedSeals},
		{"prev absent", next(1, func(h *types.Header) { setX(h, func(x *types.WBFTExtra) { x.PrevCommittedSeal = nil }) }, nil), now, "H20", ErrEmptyPrevCommittedSeals},
	}
	for _, tt := range tests {
		err := VerifyHeader(b.env(tt.now), tt.h, nil, headerOnly)
		if tt.want == nil {
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
			}
			continue
		}
		if !errors.Is(err, tt.want) || stepOf(err) != tt.step {
			t.Errorf("%s: got %v (step %q), want %v at %s", tt.name, err, stepOf(err), tt.want, tt.step)
		}
	}
	// The genesis header is accepted after H1 .. H9 without further checks.
	if err := VerifyHeader(b.env(now), b.hs[0], nil, headerOnly); err != nil {
		t.Errorf("genesis: %v", err)
	}
}

func TestVerifyHeaderBatchSemantics(t *testing.T) {
	b := newBuilder(t)
	b.build(7)
	now := uint64(t0 + 100)
	store := newBuilder(t)
	for _, h := range b.hs[1:5] {
		store.chain.add(h)
	}
	env := &Env{Config: b.cfg, Chain: store.chain, Now: b.env(now).Now}
	errs := VerifyHeaderBatch(env, []*types.Header{b.hs[5], b.hs[7]}, headerOnly)
	if errs[0] != nil || stepOf(errs[1]) != "H11" {
		t.Errorf("gap: %v", errs)
	}
	errs = VerifyHeaderBatch(env, []*types.Header{b.hs[6], b.hs[7]}, headerOnly)
	if !errors.Is(errs[0], ErrUnknownAncestor) || !errors.Is(errs[1], ErrUnknownAncestor) || stepOf(errs[1]) != "" {
		t.Errorf("first fails: %v", errs)
	}
	if len(VerifyHeaderBatch(env, nil, headerOnly)) != 0 {
		t.Error("empty batch")
	}
	ch := VerifyHeaders(context.Background(), env, b.hs[5:8], headerOnly)
	n := 0
	for err := range ch {
		if err != nil {
			t.Errorf("channel result %d: %v", n, err)
		}
		n++
	}
	if n != 3 {
		t.Errorf("%d results", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range VerifyHeaders(ctx, env, b.hs[5:8], headerOnly) {
		// the goroutine may deliver buffered results or stop; it must close
	}
}

// A-02 §8.4: CommitHeader of H with the seals of validators 0, 1, 2, the
// unchanged block hash, and the errors of seal writing in their order.
//
// Covers: WBFT-HDR-050, WBFT-HDR-051, WBFT-HDR-052, WBFT-PARAM-011
func TestCommitHeaderWorkedExample(t *testing.T) {
	acc := accounts(t, 3)
	reveal, _ := ecdsa.SignData(codec.RandaoData(big.NewInt(8282), types.HeightFromUint64(2)), acc[0].key)
	empty := keccak.Sum256([]byte{0x80})
	_ = empty
	txRoot, _ := hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	h := &types.Header{
		ParentHash: types.Hash(bytes.Repeat([]byte{0x11}, 32)), UncleHash: types.EmptyUncleHash, Coinbase: acc[0].addr,
		Root: types.Hash(bytes.Repeat([]byte{0x22}, 32)), TxHash: types.Hash(txRoot), ReceiptHash: types.Hash(txRoot),
		Difficulty: big.NewInt(1), Number: types.HeightFromUint64(2), GasLimit: 105000000, Time: 1700000002,
		BaseFee: big.NewInt(20000000000000),
	}
	if err := codec.SetExtra(h, &types.WBFTExtra{VanityData: make([]byte, 32), RandaoReveal: reveal, GasTip: new(big.Int).SetUint64(types.InitialGasTip)}); err != nil {
		t.Fatal(err)
	}
	var ps, cs []types.SealEntry
	for i := 0; i < 3; i++ {
		ps = append(ps, types.SealEntry{Sealer: uint32(i), Seal: acc[i].bls.Sign(codec.SealData(h, 0, types.PrepareSeal)).Bytes()})
		cs = append(cs, types.SealEntry{Sealer: uint32(i), Seal: acc[i].bls.Sign(codec.SealData(h, 0, types.CommitSeal)).Bytes()})
	}
	blk, err := CommitHeader(&types.Block{Header: h}, types.RoundFromUint64(0), ps, cs)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := codec.DecodeExtra(blk.Header)
	if hex.EncodeToString(x.PreparedSeal.Sealers) != "07" || hex.EncodeToString(x.PreparedSeal.Signature)[:16] != "895488e186a03aca" ||
		hex.EncodeToString(x.CommittedSeal.Signature)[:16] != "b1d4051be1d47483" {
		t.Errorf("aggregates %x %x", x.PreparedSeal.Signature, x.CommittedSeal.Signature)
	}
	if codec.BlockHash(blk.Header) != codec.BlockHash(h) {
		t.Error("block hash changed")
	}
	if len(blk.Header.Extra) != 317 {
		t.Errorf("committed extra of %d bytes", len(blk.Header.Extra))
	}
	r, _ := types.RoundFromBig(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(3)))
	blk, _ = CommitHeader(&types.Block{Header: h}, r, ps, cs)
	if x, _ := codec.DecodeExtra(blk.Header); x.Round != 3 {
		t.Errorf("round field %d", x.Round)
	}
	if _, err := CommitHeader(&types.Block{Header: h}, r, nil, cs); !errors.Is(err, ErrInvalidPreparedSeals) {
		t.Errorf("no prepared seals: %v", err)
	}
	if _, err := CommitHeader(&types.Block{Header: h}, r, ps, nil); !errors.Is(err, ErrInvalidCommittedSeals) {
		t.Errorf("no committed seals: %v", err)
	}
	short := append([]types.SealEntry{{Sealer: 5, Seal: make([]byte, 95)}}, ps...)
	if _, err := CommitHeader(&types.Block{Header: h}, r, short, cs); !errors.Is(err, ErrInvalidSeal) {
		t.Errorf("short seal: %v", err)
	}
	if _, err := CommitHeader(&types.Block{Header: h}, r, ps, short); !errors.Is(err, ErrInvalidSeal) {
		t.Errorf("short committed seal: %v", err)
	}
	// The prepared list is checked before the committed list.
	if _, err := CommitHeader(&types.Block{Header: h}, r, nil, nil); !errors.Is(err, ErrInvalidPreparedSeals) {
		t.Errorf("both lists empty: %v", err)
	}
	if _, err := CommitHeader(&types.Block{Header: h}, r, short, nil); !errors.Is(err, ErrInvalidSeal) {
		t.Errorf("short prepared seal and no committed seals: %v", err)
	}
	// A 96-byte value that is not a G2 point fails the aggregation.
	notPoint := append([]types.SealEntry{{Sealer: 5, Seal: bytes.Repeat([]byte{0xff}, 96)}}, ps...)
	for name, lists := range map[string][2][]types.SealEntry{"prepared": {notPoint, cs}, "committed": {ps, notPoint}} {
		_, err := CommitHeader(&types.Block{Header: h}, r, lists[0], lists[1])
		if err == nil || errors.Is(err, ErrInvalidSeal) || errors.Is(err, ErrInvalidPreparedSeals) || errors.Is(err, ErrInvalidCommittedSeals) {
			t.Errorf("%s aggregation: %v", name, err)
		}
	}
}

// A-08 §10.2.
func TestVerifyAggregatedSealBitmap(t *testing.T) {
	acc := accounts(t, 7)
	mk := func(n int) *validator.Set {
		var addrs []types.Address
		var keys [][]byte
		for _, a := range acc[:n] {
			addrs = append(addrs, a.addr)
			keys = append(keys, a.bls.PublicKey().Bytes())
		}
		vs, _ := validator.NewSet(addrs, keys, types.ProposerPolicy{})
		return vs
	}
	agg := &types.AggregatedSeal{Sealers: types.SealerSet{0x0b, 0x01}, Signature: make([]byte, 96)}
	h := &types.Header{Number: types.HeightFromUint64(1), Difficulty: big.NewInt(1), Extra: []byte{0xca, 0x80, 0x80, 0x80, 0xc0, 0xc0, 0x80, 0xc0, 0xc0, 0x80, 0xc0}}
	if err := VerifyAggregatedSeal(mk(7), h, 0, agg, types.PrepareSeal); !errors.Is(err, ErrLackOfSealCount) {
		t.Errorf("7 validators: %v", err)
	}
	if err := VerifyAggregatedSeal(mk(5), h, 0, agg, types.PrepareSeal); !errors.Is(err, ErrSealerNotValidator) {
		t.Errorf("5 validators: %v", err)
	}
}

func TestMergeSeals(t *testing.T) {
	acc := accounts(t, 4)
	msg := []byte("seal data")
	sig := func(i int) []byte { return acc[i].bls.Sign(msg).Bytes() }
	base, _ := bls.AggregateSignatures([][]byte{sig(0), sig(1), sig(2)})
	agg := &types.AggregatedSeal{Sealers: types.SealerSet{0x07}, Signature: base.Bytes()}
	if MergeSeals(agg, nil) != agg {
		t.Error("no extra seals must return the input")
	}
	m := MergeSeals(agg, []types.SealEntry{{Sealer: 3, Seal: sig(3)}, {Sealer: 1, Seal: sig(1)}})
	all, _ := bls.AggregateSignatures([][]byte{sig(0), sig(1), sig(2), sig(3)})
	if hex.EncodeToString(m.Sealers) != "0f" || !bytes.Equal(m.Signature, all.Bytes()) {
		t.Errorf("merged %x", m.Sealers)
	}
	if hex.EncodeToString(agg.Sealers) != "07" {
		t.Error("input bitmap modified")
	}
	bad := MergeSeals(agg, []types.SealEntry{{Sealer: 3, Seal: make([]byte, 96)}})
	if bad != agg {
		t.Error("failed aggregation must return the input unchanged")
	}
	wide := MergeSeals(agg, []types.SealEntry{{Sealer: 9, Seal: sig(3)}})
	if hex.EncodeToString(wide.Sealers) != "0702" {
		t.Errorf("extended bitmap %x", wide.Sealers)
	}
}

// Covers: WBFT-ENC-031
func TestPrepareProposal(t *testing.T) {
	b := newBuilder(t)
	b.build(3)
	parent := b.head()
	skel := func(extra []byte) *types.Header {
		return &types.Header{ParentHash: codec.BlockHash(parent), Number: parent.Number.AddUint64(1), Extra: extra,
			GasLimit: parent.GasLimit, BaseFee: parent.BaseFee, UncleHash: types.EmptyUncleHash, Root: types.Hash{9}}
	}
	in := ProposalInputs{Coinbase: b.acc[3].addr, Signer: keySigner{b.acc[3].key}, ParentGasTip: b.tip}
	h, err := PrepareProposal(b.env(parent.Time+100), skel([]byte("wbft")), in)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := codec.DecodeExtra(h)
	if !bytes.Equal(x.VanityData, append([]byte("wbft"), make([]byte, 28)...)) {
		t.Errorf("vanity %x", x.VanityData)
	}
	if h.Time != parent.Time+100 || h.Coinbase != b.acc[3].addr || h.Difficulty.Int64() != 1 || h.Nonce != (types.Nonce{}) {
		t.Errorf("fields: time %d coinbase %x", h.Time, h.Coinbase)
	}
	px, _ := codec.DecodeExtra(parent)
	if x.PrevRound != px.Round || !bytes.Equal(x.PrevPreparedSeal.Signature, px.PreparedSeal.Signature) {
		t.Error("previous seals not copied")
	}
	if x.GasTip.Uint64() != types.InitialGasTip {
		t.Errorf("gas tip %s", x.GasTip)
	}
	if h.MixDigest != RandaoMix(parent.MixDigest, x.RandaoReveal) {
		t.Error("mix digest")
	}
	// The time is parent.Time + period when the clock is behind.
	if h, _ := PrepareProposal(b.env(0), skel(nil), in); h.Time != parent.Time+1 {
		t.Errorf("time %d", h.Time)
	}
	if _, err := PrepareProposal(b.env(0), skel(bytes.Repeat([]byte{1}, 32)), in); err == nil {
		t.Error("undecodable 32-byte vanity accepted")
	}
	noTip := in
	noTip.ParentGasTip = nil
	if _, err := PrepareProposal(b.env(0), skel(nil), noTip); !errors.Is(err, ErrGasTipUnavailable) {
		t.Errorf("no gas tip: %v", err)
	}
	unknown := skel(nil)
	unknown.ParentHash = types.Hash{1}
	if _, err := PrepareProposal(b.env(0), unknown, in); !errors.Is(err, ErrUnknownAncestor) {
		t.Errorf("unknown parent: %v", err)
	}
	skipped := skel(nil)
	skipped.Number = parent.Number.AddUint64(2)
	if _, err := PrepareProposal(b.env(0), skipped, in); !errors.Is(err, ErrUnknownAncestor) {
		t.Errorf("number not parent + 1: %v", err)
	}
	opt := in
	opt.Allow32ByteVanity = true
	if _, err := PrepareProposal(b.env(0), skel(nil), opt); !errors.Is(err, ErrUnsupportedOption) {
		t.Errorf("reserved option: %v", err)
	}
	// A stored head without seals cannot carry previous seals.
	unsealed := b.propose(3, nil, nil)
	b.store(unsealed)
	nextSkel := &types.Header{ParentHash: codec.BlockHash(unsealed), Number: unsealed.Number.AddUint64(1), GasLimit: unsealed.GasLimit, BaseFee: unsealed.BaseFee}
	if _, err := PrepareProposal(b.env(0), nextSkel, in); !errors.Is(err, ErrEmptyPreparedSeals) {
		t.Errorf("unsealed head: %v", err)
	}
}

type staticSnapshots map[types.Hash]*source.AuthoritySnapshot

func (s staticSnapshots) Get(h types.Hash) (*source.AuthoritySnapshot, bool) {
	x, ok := s[h]
	return x, ok
}

func TestStateDependentSteps(t *testing.T) {
	b := newBuilder(t)
	b.build(3)
	h := b.seal(b.propose(3, nil, nil), 0, []int{0, 1, 2})
	parentHash := h.ParentHash
	env := b.env(t0 + 100)
	snap := func(tip uint64, black ...types.Address) {
		s, err := source.NewAuthoritySnapshot(types.HeightFromUint64(3), parentHash, uint256.NewInt(tip), b.set(h, nil).Addresses(), black, nil)
		if err != nil {
			t.Fatal(err)
		}
		env.Snapshots = staticSnapshots{parentHash: s}
	}
	snap(types.InitialGasTip)
	if err := VerifyHeader(env, h, nil, headerOnly); err != nil {
		t.Errorf("with snapshot: %v", err)
	}
	snap(types.InitialGasTip, b.acc[3].addr)
	if err := VerifyHeader(env, h, nil, headerOnly); !errors.Is(err, ErrBlacklistedSigner) || stepOf(err) != "H15b" {
		t.Errorf("blacklisted: %v", err)
	}
	snap(1)
	if err := VerifyHeader(env, h, nil, headerOnly); !errors.Is(err, ErrGasTipMismatch) || stepOf(err) != "H21" {
		t.Errorf("gas tip: %v", err)
	}
	env.Snapshots = nil
	if err := VerifyHeader(env, h, nil, headerOnly); err != nil {
		t.Errorf("header-only without snapshot: %v", err)
	}
	if err := VerifyHeader(env, h, nil, Options{CheckSeals: true, Mode: Proposal}); !errors.Is(err, ErrSnapshotMissing) {
		t.Errorf("proposal without snapshot: %v", err)
	}
	if err := CheckGasTip(h, uint256.NewInt(types.InitialGasTip)); err != nil {
		t.Errorf("CheckGasTip: %v", err)
	}
}

// Covers: WBFT-HDR-060, WBFT-HDR-061, WBFT-HDR-063
func TestVerifyProposal(t *testing.T) {
	b := newBuilder(t)
	b.build(3)
	h := b.propose(3, nil, nil)
	blk := &types.Block{Header: h}
	env := b.env(t0 + 100)
	s, _ := source.NewAuthoritySnapshot(types.HeightFromUint64(3), h.ParentHash, b.tip, b.set(h, nil).Addresses(), nil, nil)
	env.Snapshots = staticSnapshots{h.ParentHash: s}
	if _, err := VerifyProposal(env, blk); err != nil {
		t.Fatalf("valid proposal: %v", err)
	}
	if _, err := VerifyProposal(env, nil); stepOf(err) != "P1" {
		t.Errorf("nil block: %v", err)
	}
	bad := *env
	bad.BadBlock = func(types.Hash) bool { return true }
	if _, err := VerifyProposal(&bad, blk); stepOf(err) != "P2" {
		t.Errorf("bad block: %v", err)
	}
	early := b.env(h.Time - 5)
	early.Snapshots = env.Snapshots
	d, err := VerifyProposal(early, blk)
	if !errors.Is(err, ErrFutureBlock) || d != 5*time.Second {
		t.Errorf("future: %v %v", d, err)
	}
	// The bad-block check (P2) comes before the future check (P6).
	earlyBad := *early
	earlyBad.BadBlock = bad.BadBlock
	if _, err := VerifyProposal(&earlyBad, blk); stepOf(err) != "P2" {
		t.Errorf("bad block from the future: %v", err)
	}
	// Far in the future the duration saturates; from 2^63 on it is negative.
	for _, tt := range []struct {
		time uint64
		want func(time.Duration) bool
	}{
		{1 << 62, func(d time.Duration) bool { return d == time.Duration(math.MaxInt64) }},
		{1 << 63, func(d time.Duration) bool { return d < 0 }},
		{math.MaxUint64, func(d time.Duration) bool { return d < 0 }},
	} {
		fh := h.Copy()
		fh.Time = tt.time
		d, err := VerifyProposal(env, &types.Block{Header: fh})
		if !errors.Is(err, ErrFutureBlock) || !tt.want(d) {
			t.Errorf("time %d: %v %v", tt.time, d, err)
		}
	}
}

// Round and seals of a finalized header are node-local: a verifier whose
// stored copy of block n carries another round and other sealers than the
// proposer's copy still accepts block n+1.
//
// Covers: WBFT-HDR-053
func TestNodeLocalSeals(t *testing.T) {
	b := newBuilder(t)
	b.build(6)
	h7 := b.seal(b.propose(1, nil, nil), 0, []int{0, 1, 2})
	orig := b.hs[6]
	alt := b.seal(orig.Copy(), 1, []int{1, 2, 3})
	if codec.BlockHash(alt) != codec.BlockHash(orig) {
		t.Fatal("resealed copy has another hash")
	}
	ox, _ := codec.DecodeExtra(orig)
	ax, _ := codec.DecodeExtra(alt)
	x7, _ := codec.DecodeExtra(h7)
	if ax.Round == ox.Round || bytes.Equal(ax.PreparedSeal.Sealers, x7.PrevPreparedSeal.Sealers) || x7.PrevRound != ox.Round {
		t.Fatal("fixture: the copies do not differ as intended")
	}
	now := uint64(t0 + 100)
	for name, stored := range map[string]*types.Header{"same copy": orig, "other copy": alt} {
		b.chain.add(stored)
		if err := VerifyHeader(b.env(now), alt, nil, headerOnly); err != nil {
			t.Errorf("%s: block 6: %v", name, err)
		}
		if err := VerifyHeader(b.env(now), h7, nil, headerOnly); err != nil {
			t.Errorf("%s: block 7: %v", name, err)
		}
	}
}

func TestVerifyLight(t *testing.T) {
	b := newBuilder(t)
	b.build(7)
	trust := trustChain{b}
	in := LightInputs{Config: b.cfg, Trusted: trust}
	for i := 1; i <= 7; i++ {
		if r, err := VerifyLight(in, b.hs[i], b.hs[i-1]); r != Valid {
			t.Errorf("block %d: %s %v", i, r, err)
		}
	}
	if r, _ := VerifyLight(in, b.hs[0], nil); r != CannotDecide {
		t.Errorf("genesis: %s", r)
	}
	if r, _ := VerifyLight(in, b.hs[3], nil); r != CannotDecide {
		t.Errorf("missing parent: %s", r)
	}
	// An epoch block without EpochInfo is invalid.
	h := b.hs[4].Copy()
	b.setEpochInfo(h, nil)
	if r, _ := VerifyLight(in, h, b.hs[3]); r != Invalid {
		t.Errorf("epoch block without EpochInfo: %s", r)
	}
	d := b.hs[5].Copy()
	d.Difficulty = big.NewInt(2)
	if r, err := VerifyLight(in, d, b.hs[4]); r != Invalid || stepOf(err) != "H4" {
		t.Errorf("difficulty: %s %v", r, err)
	}
}

type trustChain struct{ b *builder }

func (t trustChain) ValidatorsAt(n types.Height, parent types.Hash) (*validator.Set, error) {
	return validator.ValidatorsAt(t.b.chain, t.b.cfg, n, parent, nil)
}

// A-02 §8.5.
func TestRandaoMix(t *testing.T) {
	acc := accounts(t, 1)
	reveal, _ := ecdsa.SignData(codec.RandaoData(big.NewInt(8282), types.HeightFromUint64(1)), acc[0].key)
	if hex.EncodeToString(reveal) != "c2384d0a5f278af89e4a50f9cb4bab11e13b47a9326bad7dd80676f3b64a8afd5838925a1c50009cdfdfca97b92b95e483bed47591461bbab3d3efa442c8027900" {
		t.Fatalf("reveal %x", reveal)
	}
	if m := RandaoMix(types.Hash{}, reveal); hex.EncodeToString(m[:]) != "02d9a1f0741587237b57b8ef79de5d93e99fbac76077a26c03ad4139f01769af" {
		t.Errorf("mix %x", m)
	}
	var p types.Hash
	for i := range p {
		if i%2 == 1 {
			p[i] = 0xff
		}
	}
	if m := RandaoMix(p, reveal); hex.EncodeToString(m[:]) != "0226a10f74ea87dc7ba8b81079215d6ce960ba386088a293035241c6f0e86950" {
		t.Errorf("mix %x", m)
	}
	if m := RandaoMix(keccak.Sum256(reveal), reveal); m != (types.Hash{}) {
		t.Errorf("self mix %x", m)
	}
}

// block_period is taken from config_at of the header being built or
// verified: with a transition to a 10-second period at block 3, block 3 must
// be at least 10 seconds after block 2 while block 2 needs 1 second.
//
// Covers: WBFT-PARAM-053
func TestBlockPeriodConfigAt(t *testing.T) {
	b := newBuilder(t)
	pol := uint64(0)
	b.cfg = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: &pol},
		[]types.Transition{{Block: big.NewInt(3), WBFT: &types.WBFTParams{BlockPeriodSeconds: 10}}}, b.cfg.Init, b.cfg.ChainID)
	b.build(2)
	if got := b.hs[2].Time - b.hs[1].Time; got != 1 {
		t.Fatalf("block 2 is %d s after block 1, want 1", got)
	}
	parent := b.head()
	h3 := b.propose(2, nil, nil) // the clock is at the parent time
	if h3.Time != parent.Time+10 {
		t.Fatalf("block 3 time %d, want parent + 10", h3.Time)
	}
	now := parent.Time + 100
	if err := VerifyHeader(b.env(now), b.seal(h3, 0, []int{1, 2, 3}), nil, headerOnly); err != nil {
		t.Errorf("block 3 at parent + 10: %v", err)
	}
	early := b.propose(2, nil, nil)
	early.Time = parent.Time + 9
	resigned := b.seal(early, 0, []int{1, 2, 3})
	if err := VerifyHeader(b.env(now), resigned, nil, headerOnly); !errors.Is(err, ErrInvalidTimestamp) || stepOf(err) != "H12" {
		t.Errorf("block 3 at parent + 9: %v", err)
	}
}
