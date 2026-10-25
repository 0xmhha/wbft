package window_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	state "github.com/0xmhha/wbft/chain/window"
	"github.com/0xmhha/wbft/codec"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
)

type history struct {
	headers    map[types.Hash]*types.Header
	members    map[types.Hash][]wire.Member
	limits     wire.Limits
	activation types.Height
}

func (h *history) Header(hash types.Hash, n types.Height) (*types.Header, error) {
	v := h.headers[hash]
	if v == nil || v.Number.Cmp(n) != 0 {
		return nil, state.ErrHistory
	}
	return v.Copy(), nil
}
func (h *history) Authority(target *types.Header) ([]wire.Member, error) {
	hash, err := h.hash(target)
	if err != nil {
		return nil, err
	}
	members, ok := h.members[hash]
	if !ok {
		return nil, state.ErrHistory
	}
	return members, nil
}
func (h *history) hash(header *types.Header) (types.Hash, error) {
	if header.Number.Cmp(h.activation) < 0 {
		return codec.BlockHash(header), nil
	}
	return wire.BlockHash(header, h.limits)
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func address(id int) types.Address { var a types.Address; a[19] = byte(id + 1); return a }
func secret(t *testing.T, id, version int) *bls.SecretKey {
	t.Helper()
	seed := sha256.Sum256([]byte(fmt.Sprintf("observation-window-test/%d/%d", id, version)))
	sk, err := bls.DeriveSecretKey(seed[:])
	must(t, err)
	return sk
}
func members(t *testing.T, n int) []wire.Member {
	ids := []int{0, 1, 2, 3}
	if n >= 7 {
		ids = []int{2, 0, 4, 3}
	}
	if n >= 13 {
		ids = []int{4, 5, 0, 1}
	}
	if n >= 19 {
		ids = []int{1, 0, 6, 2}
	}
	var out []wire.Member
	for _, id := range ids {
		version := 0
		if id == 0 && n >= 13 {
			version = 1
		}
		out = append(out, wire.Member{Address: address(id), Key: secret(t, id, version).PublicKey().Bytes()})
	}
	return out
}
func epochInfo(m []wire.Member) *types.EpochInfo {
	e := &types.EpochInfo{}
	for i, v := range m {
		e.Candidates = append(e.Candidates, types.Candidate{Addr: v.Address, Diligence: uint64(1000000 + i)})
		e.Validators = append(e.Validators, uint32(i))
		e.BLSPublicKeys = append(e.BLSPublicKeys, v.Key)
	}
	return e
}
func keyFor(t *testing.T, m wire.Member) *bls.SecretKey {
	for version := 0; version < 2; version++ {
		sk := secret(t, int(m.Address[19])-1, version)
		if bytes.Equal(sk.PublicKey().Bytes(), m.Key) {
			return sk
		}
	}
	t.Fatal("fixture key")
	return nil
}
func aggregate(t *testing.T, h *types.Header, round uint32, phase types.SealType, m []wire.Member, limits wire.Limits, include func(int) bool) (types.SealerSet, []byte) {
	t.Helper()
	msg, err := wire.SealData(h, round, phase, limits)
	must(t, err)
	var bitmap types.SealerSet
	var signatures [][]byte
	for i, v := range m {
		if include(i) {
			bitmap.SetSealer(uint32(i))
			signatures = append(signatures, keyFor(t, v).Sign(msg).Bytes())
		}
	}
	if len(signatures) == 0 {
		return nil, nil
	}
	sig, err := bls.AggregateSignatures(signatures)
	must(t, err)
	return bitmap, sig.Bytes()
}
func ownProofs(t *testing.T, headers []*types.Header, history *history, n, k int) []wire.Proof {
	var proofs []wire.Proof
	start := n - k
	if start < 1 {
		start = 1
	}
	for target := start; target < n; target++ {
		h := headers[target]
		m := members(t, target)
		hash, err := history.hash(h)
		must(t, err)
		digest, err := wire.AuthorityDigest(m, history.limits)
		must(t, err)
		for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
			bitmap, sig := aggregate(t, h, uint32(target%3), phase, m, history.limits, func(i int) bool { return (target+int(phase)+i)%(k+2)+1 <= n-target })
			if len(bitmap) > 0 {
				proofs = append(proofs, wire.Proof{Height: h.Number, Hash: hash, Round: uint32(target % 3), Authority: digest, Phase: phase, Bitmap: bitmap, Signature: sig})
			}
		}
	}
	return proofs
}
func initial(t *testing.T, k int, activation types.Height) (*state.Engine, *state.State, *history, *types.Header) {
	return initialRetention(t, k, activation, types.Height{})
}
func initialRetention(t *testing.T, k int, activation, H types.Height) (*state.Engine, *state.State, *history, *types.Header) {
	t.Helper()
	limits := wire.Limits{ExtraBytes: 65536, Proofs: 32, SettlementRows: 32, Validators: 8}
	before, _ := activation.Sub(types.HeightFromUint64(1))
	x := &types.WBFTExtra{VanityData: make([]byte, 32), EpochInfo: epochInfo(members(t, 1))}
	raw, err := codec.EncodeExtra(x)
	must(t, err)
	parent := &types.Header{Number: before, Difficulty: big.NewInt(1), GasLimit: 30000000, Extra: raw}
	hash := codec.BlockHash(parent)
	cfg := state.Config{ChainID: big.NewInt(88001), GenesisHash: hash, Activation: activation, Window: uint64(k), Codec: limits, StateBytes: 65536, CheckpointBytes: 131072, AddressRows: 32}
	var engine *state.Engine
	if H.IsZero() {
		engine, err = state.New(cfg)
	} else {
		engine, err = state.NewRecent(cfg, H)
	}
	must(t, err)
	s, err := engine.Initial(parent)
	must(t, err)
	history := &history{headers: map[types.Hash]*types.Header{hash: parent}, members: map[types.Hash][]wire.Member{hash: members(t, 0)}, limits: limits, activation: activation}
	return engine, s, history, parent
}

type closed struct {
	engine  *state.Engine
	history *history
	headers []*types.Header
	states  []*state.State
}

func normal(t *testing.T, k int, activation types.Height) closed {
	return normalScenario(t, k, activation, false)
}

func normalScenario(t *testing.T, k int, activation types.Height, previousCertificates bool) closed {
	return normalRetention(t, k, activation, previousCertificates, types.Height{}, 24)
}
func normalRetention(t *testing.T, k int, activation types.Height, previousCertificates bool, H types.Height, blocks int) closed {
	t.Helper()
	engine, s, hist, parent := initialRetention(t, k, activation, H)
	headers := []*types.Header{parent}
	states := []*state.State{s}
	observed := map[string]map[types.Address][2]bool{}
	opportunities := map[string][]wire.Member{}
	var readState = *s
	for n := 1; n <= blocks; n++ {
		legacy := &types.WBFTExtra{VanityData: make([]byte, 32), GasTip: big.NewInt(7), PrevRound: uint32((n - 1) % 3)}
		if n%6 == 0 {
			legacy.EpochInfo = epochInfo(members(t, n+1))
		}
		if previousCertificates && n > 1 {
			parentExtra, err := wire.Decode(headers[n-1].Extra, hist.limits)
			must(t, err)
			legacy.PrevPreparedSeal = parentExtra.Legacy.PreparedSeal.Copy()
			legacy.PrevCommittedSeal = parentExtra.Legacy.CommittedSeal.Copy()
		}
		raw, err := codec.EncodeExtra(legacy)
		must(t, err)
		original := append([]byte(nil), raw...)
		parentHash, err := hist.hash(headers[n-1])
		must(t, err)
		candidate := &types.Header{ParentHash: parentHash, Number: activation.AddUint64(uint64(n - 1)), Difficulty: big.NewInt(1), GasLimit: 30000000, Extra: raw}
		proofs := ownProofs(t, headers, hist, n, k)
		beforeRoot, err := engine.Root(s)
		must(t, err)
		carrier, next, err := engine.Build(s, candidate, proofs, hist)
		must(t, err)
		if !bytes.Equal(candidate.Extra, original) {
			t.Fatal("legacy input mutated")
		}
		still, err := engine.Root(s)
		must(t, err)
		if still != beforeRoot {
			t.Fatal("parent mutated")
		}
		decoded, err := wire.Decode(carrier.Extra, hist.limits)
		must(t, err)
		legacyBytes, err := codec.EncodeExtra(decoded.Legacy)
		must(t, err)
		if !bytes.Equal(legacyBytes, original) {
			t.Fatal("legacy epoch/diligence fields changed")
		}
		// Normal own quorum certificates remain distinct from subset observations.
		for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
			bitmap, sig := aggregate(t, carrier, uint32(n%3), phase, members(t, n), hist.limits, func(int) bool { return true })
			var addrs []types.Address
			var keys [][]byte
			for _, m := range members(t, n) {
				addrs = append(addrs, m.Address)
				keys = append(keys, m.Key)
			}
			set, err := validator.NewSet(addrs, keys, types.ProposerPolicy{ID: types.RoundRobin})
			must(t, err)
			if len(bitmap.Sealers()) < set.Quorum() {
				t.Fatal("finality weakened")
			}
			seal := &types.AggregatedSeal{Sealers: bitmap, Signature: sig}
			if phase == types.PrepareSeal {
				decoded.Legacy.PreparedSeal = seal
			} else {
				decoded.Legacy.CommittedSeal = seal
			}
		}
		decoded.Legacy.Round = uint32(n % 3)
		carrier.Extra, err = wire.Encode(decoded, hist.limits)
		must(t, err)
		applied, err := engine.Apply(&readState, carrier, hist)
		must(t, err)
		builtRoot, err := engine.Root(next)
		must(t, err)
		appliedRoot, err := engine.Root(applied)
		must(t, err)
		if builtRoot != appliedRoot {
			t.Fatal("builder/independent reader")
		}
		hash, err := hist.hash(carrier)
		must(t, err)
		hist.headers[hash] = carrier
		hist.members[hash] = members(t, n)
		headers = append(headers, carrier)
		states = append(states, applied)
		s = applied
		readState = *applied
		opportunities[carrier.Number.String()] = members(t, n)
		for _, proof := range proofs {
			key := proof.Height.String()
			if observed[key] == nil {
				observed[key] = map[types.Address][2]bool{}
			}
			targetN := int(new(big.Int).Sub(proof.Height.Big(), activation.Big()).Int64()) + 1
			for _, index := range types.SealerSet(proof.Bitmap).Sealers() {
				a := members(t, targetN)[index].Address
				value := observed[key][a]
				value[int(proof.Phase)] = true
				observed[key][a] = value
			}
		}
		// Directly enumerate all settled historical targets and recorded bitmap
		// unions; this oracle does not call the transition's count accumulator.
		for id := 0; id < 8; id++ {
			a := address(id)
			eligible, prep, commit := 0, 0, 0
			for target := 1; target <= n; target++ {
				height := activation.AddUint64(uint64(target - 1))
				if height.Cmp(s.SettledThrough()) > 0 {
					break
				}
				if !H.IsZero() {
					from, _, _ := s.SettledWindow()
					if height.Cmp(from) < 0 {
						continue
					}
				}
				for _, m := range opportunities[height.String()] {
					if m.Address == a {
						eligible++
						v := observed[height.String()][a]
						if v[0] {
							prep++
						}
						if v[1] {
							commit++
						}
					}
				}
			}
			got, ok := s.Counts(a)
			if ok != (eligible > 0) || got.EligiblePrepare.Cmp(big.NewInt(int64(eligible))) != 0 || got.EligibleCommit.Cmp(big.NewInt(int64(eligible))) != 0 || got.ObservedPrepare.Cmp(big.NewInt(int64(prep))) != 0 || got.ObservedCommit.Cmp(big.NewInt(int64(commit))) != 0 {
				t.Fatalf("oracle n=%d address=%d", n, id)
			}
		}
		if !H.IsZero() {
			from := activation
			if v, ok := s.MaturedThrough().AddUint64(1).Sub(H); ok && v.Cmp(from) > 0 {
				from = v
			}
			gotFrom, gotThrough, ok := s.RecentWindow()
			if !ok || gotFrom.Cmp(from) != 0 || gotThrough.Cmp(s.MaturedThrough()) != 0 {
				t.Fatal("retained window cursor")
			}
			for id := 0; id < 8; id++ {
				a := address(id)
				eligible, prep, commit := 0, 0, 0
				for target := 1; target <= n; target++ {
					height := activation.AddUint64(uint64(target - 1))
					if height.Cmp(s.MaturedThrough()) > 0 {
						break
					}
					if height.Cmp(from) < 0 {
						continue
					}
					for _, m := range opportunities[height.String()] {
						if m.Address == a {
							eligible++
							v := observed[height.String()][a]
							if v[0] {
								prep++
							}
							if v[1] {
								commit++
							}
						}
					}
				}
				got, has := s.RecentCounts(a)
				if has != (eligible > 0) || got.EligiblePrepare.Cmp(big.NewInt(int64(eligible))) != 0 || got.ObservedPrepare.Cmp(big.NewInt(int64(prep))) != 0 || got.ObservedCommit.Cmp(big.NewInt(int64(commit))) != 0 {
					t.Fatalf("recent oracle n=%d address=%d", n, id)
				}
			}
		}
		if n == 6 || n == 12 || n == 23 {
			cp, err := engine.EncodeCheckpoint(s, carrier)
			must(t, err)
			restored, err := engine.Recover(cp, carrier)
			must(t, err)
			readState = *restored
		}
	}
	return closed{engine, hist, headers, states}
}

func TestNormalHistorySettlementAndRecovery(t *testing.T) {
	for _, k := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("window_%d", k), func(t *testing.T) { normal(t, k, types.HeightFromUint64(1)) })
	}
}
func TestFullHeightHistoryUsesNoLow64Index(t *testing.T) {
	high := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(9))
	normal(t, 4, types.MustHeightFromBig(high))
}

func TestClosedCheckpointAndCarrierCopies(t *testing.T) {
	c := normal(t, 2, types.HeightFromUint64(1))
	h := c.headers[24]
	s := c.states[24]
	cp, err := c.engine.EncodeCheckpoint(s, h)
	must(t, err)
	if _, err = c.engine.Recover(cp, c.headers[23]); err == nil {
		t.Fatal("wrong trusted anchor")
	}
	copyBytes := append(append([]byte(nil), cp...), 0)
	if _, err = c.engine.Recover(copyBytes, h); err == nil {
		t.Fatal("noncanonical checkpoint")
	}
	x, err := wire.Decode(h.Extra, c.history.limits)
	must(t, err)
	x.Observation.ResultStateRoot[0] ^= 1
	copyHeader := h.Copy()
	copyHeader.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	parent := c.states[23]
	before, err := c.engine.Root(parent)
	must(t, err)
	if _, err = c.engine.Apply(parent, copyHeader, c.history); !errors.Is(err, state.ErrCommitment) {
		t.Fatal("copied root accepted", err)
	}
	x, err = wire.Decode(h.Extra, c.history.limits)
	must(t, err)
	x.Observation.Settlement.Previous = x.Observation.Settlement.Previous.AddUint64(1)
	copyHeader.Extra, err = wire.Encode(x, c.history.limits)
	must(t, err)
	if _, err = c.engine.Apply(parent, copyHeader, c.history); !errors.Is(err, state.ErrCommitment) {
		t.Fatal("copied settlement cursor accepted", err)
	}
	after, err := c.engine.Root(parent)
	must(t, err)
	if before != after {
		t.Fatal("failed apply changed parent")
	}
	changed := h.Copy()
	changed.ParentHash[0] ^= 1
	if _, err = c.engine.Apply(parent, changed, c.history); err == nil {
		t.Fatal("wrong branch")
	}
	// A sealed proposal's hash-bound witnesses cannot be rebuilt.
	legacy, err := codec.EncodeExtra(x.Legacy)
	must(t, err)
	sealed := h.Copy()
	sealed.Extra = legacy
	if _, _, err = c.engine.Build(parent, sealed, nil, c.history); !errors.Is(err, state.ErrState) {
		t.Fatal("sealed candidate rebuilt", err)
	}
}
