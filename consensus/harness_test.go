package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// fakeEnv answers the core's Env calls from fields a test sets.
type fakeEnv struct {
	head           *types.Block
	vs             *validator.Set
	vsErr          error
	invalid        map[types.Hash]bool
	future         map[types.Hash]time.Duration
	bad            map[types.Hash]bool
	finalizeFail   bool
	validateCalls  int
	commitCalls    int
	lastPrepared   []types.SealEntry
	lastCommitted  []types.SealEntry
	lastCommitRnd  types.Round
	validatedBlock []types.Hash
}

func (e *fakeEnv) Head() HeadInfo {
	return HeadInfo{Header: e.head.Header, Proposer: types.ProposerOf(e.head.Header)}
}

func (e *fakeEnv) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) {
	if e.vsErr != nil {
		return nil, e.vsErr
	}
	return e.vs, nil
}

var errTestInvalid = errors.New("test: invalid proposal")

func (e *fakeEnv) ValidateProposal(b *types.Block) (time.Duration, error) {
	e.validateCalls++
	h := blockHash(b)
	e.validatedBlock = append(e.validatedBlock, h)
	if e.invalid[h] {
		return 0, errTestInvalid
	}
	if d, ok := e.future[h]; ok {
		return d, fmt.Errorf("test: %w", header.ErrFutureBlock)
	}
	return 0, nil
}

func (e *fakeEnv) IsBadBlock(h types.Hash) bool { return e.bad[h] }

func (e *fakeEnv) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	e.commitCalls++
	e.lastPrepared, e.lastCommitted, e.lastCommitRnd = prepared, committed, round
	if e.finalizeFail {
		return nil, errors.New("test: finalize fails")
	}
	return header.CommitHeader(b, round, prepared, committed)
}

// harness drives one core with n validators whose keys are those of the
// specification's vectors. The head is block 9 proposed by the last
// validator, so the proposer of (10, r) is validator r mod n.
type harness struct {
	t     *testing.T
	n     int
	self  int
	keys  []*ecdsa.PrivateKey
	blsK  []*bls.SecretKey
	addrs []types.Address
	vs    *validator.Set
	env   *fakeEnv
	s     *State
	cfg   *types.Config
	out   []Output // outputs of the last step
}

func vectorKey(i int) []byte {
	return keccak.Sum256Bytes([]byte("wbft-spec-vector-key-" + strconv.Itoa(i)))
}

func newHarness(t *testing.T, n, self int) *harness {
	t.Helper()
	h := &harness{t: t, n: n, self: self}
	blsPub := make([][]byte, n)
	for i := 0; i < n; i++ {
		k, err := ecdsa.PrivateKeyFromBytes(vectorKey(i))
		if err != nil {
			t.Fatal(err)
		}
		b, err := bls.DeriveSecretKey(vectorKey(i))
		if err != nil {
			t.Fatal(err)
		}
		h.keys = append(h.keys, k)
		h.blsK = append(h.blsK, b)
		h.addrs = append(h.addrs, ecdsa.Address(k))
		blsPub[i] = b.PublicKey().Bytes()
	}
	vs, err := validator.NewSet(h.addrs, blsPub, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	h.vs = vs
	policy := uint64(0)
	h.cfg = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)
	h.env = &fakeEnv{
		head:    h.block(9, 0, h.addrs[n-1]),
		vs:      vs,
		invalid: map[types.Hash]bool{},
		future:  map[types.Hash]time.Duration{},
		bad:     map[types.Hash]bool{},
	}
	var selfAddr types.Address
	if self >= 0 {
		selfAddr = h.addrs[self]
	}
	h.s = NewState(Options{Config: h.cfg, Self: selfAddr})
	return h
}

// block returns a block with the given number whose content depends on tag.
func (h *harness) block(number uint64, tag byte, coinbase types.Address) *types.Block {
	h.t.Helper()
	vanity := make([]byte, types.ExtraVanity)
	vanity[0] = tag
	extra, err := codec.EncodeExtra(&types.WBFTExtra{VanityData: vanity, RandaoReveal: []byte{}})
	if err != nil {
		h.t.Fatal(err)
	}
	hd := &types.Header{
		ParentHash: types.Hash{byte(number), tag},
		UncleHash:  types.EmptyUncleHash,
		Coinbase:   coinbase,
		Difficulty: big.NewInt(1),
		Number:     types.HeightFromUint64(number),
		GasLimit:   30_000_000,
		Time:       1_700_000_000 + number,
		Extra:      extra,
	}
	return &types.Block{Header: hd, Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

func (h *harness) proposal(tag byte) *types.Block {
	return h.block(10, tag, h.addrs[0])
}

func view(seq, round uint64) types.View {
	return types.View{Sequence: types.HeightFromUint64(seq), Round: types.RoundFromUint64(round)}
}

// step feeds one input and keeps its outputs.
func (h *harness) step(in Input) []Output {
	h.out = h.s.Step(h.env, in)
	return h.out
}

func (h *harness) start() []Output { return h.step(Start{}) }

// signed signs m as validator i: the BLS seal over sealData (if any), then
// the ECDSA signature.
func (h *harness) signed(i int, m *codec.Message, sealData []byte) *codec.Message {
	h.t.Helper()
	c := *m
	if sealData != nil {
		c.Seal = h.blsK[i].Sign(sealData).Bytes()
	}
	p, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if c.Signature, err = ecdsa.SignData(p, h.keys[i]); err != nil {
		h.t.Fatal(err)
	}
	return &c
}

func (h *harness) encode(m *codec.Message) []byte {
	h.t.Helper()
	b, err := codec.EncodeMessage(m)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// deliver feeds m as a message received from validator i's peer.
func (h *harness) deliver(peer int, m *codec.Message) []Output {
	return h.step(Message{Code: m.Code, Payload: h.encode(m), Peer: h.addrs[peer]})
}

func (h *harness) preprepare(i int, v types.View, b *types.Block, rcs, ps []*codec.Message) *codec.Message {
	return h.signed(i, &codec.Message{Code: codec.CodePreprepare, View: v, Proposal: b, RoundChanges: rcs, Prepares: ps}, nil)
}

func (h *harness) vote(i int, code codec.Code, v types.View, b *types.Block) *codec.Message {
	t := types.PrepareSeal
	if code == codec.CodeCommit {
		t = types.CommitSeal
	}
	return h.signed(i, &codec.Message{Code: code, View: v, Digest: blockHash(b)}, codec.SealData(b.Header, uint32(v.Round.RefLow64()), t))
}

func (h *harness) prepare(i int, v types.View, b *types.Block) *codec.Message {
	return h.vote(i, codec.CodePrepare, v, b)
}

func (h *harness) commit(i int, v types.View, b *types.Block) *codec.Message {
	return h.vote(i, codec.CodeCommit, v, b)
}

// roundChange returns ROUND-CHANGE(v) of validator i, prepared on (pr, pb)
// with the PREPAREs ps when pb is not nil.
func (h *harness) roundChange(i int, v types.View, pr *types.Round, pb *types.Block, ps []*codec.Message) *codec.Message {
	m := &codec.Message{Code: codec.CodeRoundChange, View: v, PreparedRound: pr, PreparedBlock: pb, Prepares: ps}
	if pb != nil {
		m.PreparedDigest = blockHash(pb)
	}
	return h.signed(i, m, nil)
}

// selfDeliver signs a Broadcast output as the node and delivers it back.
func (h *harness) selfDeliver(b Broadcast) []Output {
	return h.step(Message{Code: b.Msg.Code, Payload: h.encode(h.signed(h.self, b.Msg, b.SealData)), Peer: h.addrs[h.self]})
}

// broadcasts returns the Broadcast outputs of the last step.
func (h *harness) broadcasts() []Broadcast { return outputsOf[Broadcast](h.out) }

func outputsOf[T Output](outs []Output) []T {
	var r []T
	for _, o := range outs {
		if x, ok := o.(T); ok {
			r = append(r, x)
		}
	}
	return r
}

// outcome returns the Outcome of the last step.
func (h *harness) outcome() Outcome {
	h.t.Helper()
	os := outputsOf[Outcome](h.out)
	if len(os) != 1 {
		h.t.Fatalf("%d outcomes in %v", len(os), h.out)
	}
	return os[0]
}

// expect checks the class, row and relay flag of the last message.
func (h *harness) expect(check Class, row int, relayed bool) {
	h.t.Helper()
	o := h.outcome()
	if o.Check != check || o.Row != row || o.Relayed != relayed {
		h.t.Fatalf("outcome %s row %d relayed %t, want %s row %d relayed %t", o.Check, o.Row, o.Relayed, check, row, relayed)
	}
	relays := outputsOf[Relay](h.out)
	if relayed != (len(relays) == 1) {
		h.t.Fatalf("relay outputs %v, relayed %t", relays, relayed)
	}
	rowsSeen[row] = true
}

// rowsSeen collects the outcome rows the tests of this package checked.
var rowsSeen = map[int]bool{}

// roundTimeout fires the current round timer.
func (h *harness) roundTimeout() []Output {
	return h.step(Timeout{Kind: RoundTimer, Gen: h.s.gen[RoundTimer]})
}

func (h *harness) vars() *Vars {
	h.t.Helper()
	v := h.s.Vars()
	if v == nil {
		h.t.Fatal("no vars")
	}
	return v
}

func (h *harness) wantView(seq, round uint64, st StateName) {
	h.t.Helper()
	v := h.vars()
	if v.View.Cmp(view(seq, round)) != 0 || v.State != st {
		h.t.Fatalf("at %s/%s %s, want %d/%d %s", v.View.Sequence, v.View.Round, v.State, seq, round, st)
	}
}

// reachPrepared takes a non-proposer through PRE-PREPARE and a PREPARE quorum
// of b at (10, 0): own PREPARE and those of validators 0 and 2.
func (h *harness) reachPrepared(b *types.Block) {
	h.t.Helper()
	h.deliver(0, h.preprepare(0, view(10, 0), b, nil, nil))
	own := h.broadcasts()
	if len(own) != 1 {
		h.t.Fatalf("no PREPARE sent: %v", h.out)
	}
	h.selfDeliver(own[0])
	h.deliver(0, h.prepare(0, view(10, 0), b))
	h.deliver(2, h.prepare(2, view(10, 0), b))
	h.wantView(10, 0, Prepared)
}

// reachCommitted continues reachPrepared to the decision.
func (h *harness) reachCommitted(b *types.Block) {
	h.t.Helper()
	h.reachPrepared(b)
	own := h.broadcasts()
	if len(own) != 1 || own[0].Msg.Code != codec.CodeCommit {
		h.t.Fatalf("no COMMIT sent: %v", h.out)
	}
	h.selfDeliver(own[0])
	h.deliver(0, h.commit(0, view(10, 0), b))
	h.deliver(2, h.commit(2, view(10, 0), b))
	h.wantView(10, 0, Committed)
}

func roundPtr(r uint64) *types.Round {
	x := types.RoundFromUint64(r)
	return &x
}

// newSetOf returns the set of the first n validators of h.
func newSetOf(t *testing.T, h *harness, n int) *validator.Set {
	t.Helper()
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = h.blsK[i].PublicKey().Bytes()
	}
	vs, err := validator.NewSet(h.addrs[:n], keys, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func splitList(b []byte) ([]byte, []byte, error) { return rlp.SplitList(b) }

func listItems(t *testing.T, content []byte) [][]byte {
	t.Helper()
	items, err := rlp.Items(content)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(items))
	for i, it := range items {
		out[i] = it
	}
	return out
}

func encodeList(items ...[]byte) []byte { return rlp.EncodeList(items...) }

// secp256k1N is the order of the secp256k1 group.
var secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

// highS returns the other valid signature of the same signer: S replaced by
// n - S and the recovery byte flipped.
func highS(t *testing.T, sig []byte) []byte {
	t.Helper()
	out := append([]byte(nil), sig...)
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(secp256k1N, s)
	s.FillBytes(out[32:64])
	out[64] ^= 1
	return out
}

func signingPayload(t *testing.T, m *codec.Message) []byte {
	t.Helper()
	p, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
