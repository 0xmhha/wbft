package runner

import (
	"bytes"
	"crypto/sha256"
	"math"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

// All controls below are detached metadata models. No stored WAL, signed
// block, packet, actor, network or storage failure is changed or injected.
func historySeedModel(t *testing.T, pending bool) (validatorHistoryControl, *Runner) {
	t.Helper()
	k := newKeys(t, 4)
	head := block(t, 9, 0, k.addrs[3], types.Hash{})
	chain := &fakeChain{head: head.Header, vs: k.vs, clock: &manualClock{}}
	if pending {
		chain.vs = nil
	}
	r := &Runner{cfg: Config{Core: consensus.Options{Self: k.addrs[1], Improvements: consensus.ImprovementSet(0).With(consensus.DeferValidatorStart)}, ReplayWAL: true}, d: Deps{Chain: chain}}
	r.core = consensus.NewState(r.cfg.Core)
	r.env = &liveEnv{r: r, head: head.Header}
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlSeed,
		Before: r.core.TimerGenerations(), BeforeView: validatorHistoryAdoption(r.core), InputKind: inputlog.KindStart}
	var err error
	c.Options, err = validatorHistoryOptionsBytes(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Head, err = codec.EncodeHeader(head.Header)
	if err != nil {
		t.Fatal(err)
	}
	body, err := inputlog.Encode(consensus.Start{})
	if err != nil {
		t.Fatal(err)
	}
	c.InputHash, err = validatorHistoryInputHash(inputlog.KindStart, body)
	if err != nil {
		t.Fatal(err)
	}
	r.env.begin(false)
	outs := r.core.Step(r.env, consensus.Start{})
	for _, answer := range r.env.end() {
		w, err := validatorHistoryWitness(answer.call)
		if err != nil {
			t.Fatal(err)
		}
		c.Environment = append(c.Environment, w)
	}
	c.After, c.AfterView = r.core.TimerGenerations(), validatorHistoryAdoption(r.core)
	c.Wait, err = validatorHistoryWaitBytes(r.core.ValidatorStartWait())
	if err != nil {
		t.Fatal(err)
	}
	c.Outputs, err = inputlog.OutDigest(outs)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func TestValidatorStartProfileSeedAndCanonicalControls(t *testing.T) {
	for _, pending := range []bool{false, true} {
		seed, _ := historySeedModel(t, pending)
		record, err := encodeValidatorHistoryControl(walRunStart, seed)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeValidatorHistoryControl(record)
		if err != nil || decoded.Mode != validatorControlSeed || len(decoded.Environment) != 1 {
			t.Fatal("seed query source lost", err)
		}
		again, err := encodeValidatorHistoryControl(walRunStart, decoded)
		if err != nil || !bytes.Equal(record.Body, again.Body) {
			t.Fatal("noncanonical control roundtrip", err)
		}
		wait, err := decodeValidatorHistoryWait(decoded.Wait)
		if err != nil || (wait != nil) != pending {
			t.Fatal("initial not-adopted state lost", err)
		}
		if pending && (decoded.AfterView.Adopted != 0 || wait.Target.CmpUint64(10) != 0 || wait.Generation != decoded.After[4]) {
			t.Fatal("pending was replaced by a ready seed")
		}
		anchor, err := validatorHistoryRecordHash(record)
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := validatorHistoryPrefix(types.Hash{}, record)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := wal.Encode(record)
		if err != nil {
			t.Fatal(err)
		}
		if anchor != sha256.Sum256(frame) || prefix != sha256.Sum256(append(make([]byte, 32), frame...)) {
			t.Fatal("anchor/prefix omitted exact functional frame bytes")
		}
		resume := decoded
		resume.Mode, resume.Anchor, resume.Prefix = validatorControlResume, anchor, prefix
		resume.Records, resume.Bytes = 1, uint64(len(frame))
		resume.Options, resume.Environment = nil, nil
		resume.InputKind, resume.InputHash = "", types.Hash{}
		resume.Outputs = types.Hash{}
		resume.Before, resume.BeforeView = resume.After, resume.AfterView
		if _, err := encodeValidatorHistoryControl(walRunStart, resume); err != nil {
			t.Fatal("seed-only resume shape rejected", err)
		}
	}
}

func TestValidatorStartProfileKeepsPendingTargetApartFromEnvHead(t *testing.T) {
	seed, r := historySeedModel(t, true)
	oldWait := r.core.ValidatorStartWait()
	lower := block(t, 8, 0, types.Address{}, types.Hash{})
	r.env.head = lower.Header
	outs := r.core.Step(r.env, consensus.NewHead{Header: lower.Header})
	if len(outs) != 0 || r.core.ValidatorStartWait().Target.Cmp(oldWait.Target) != 0 {
		t.Fatal("normal source model did not retain its target")
	}
	c := seed
	c.Mode, c.Options, c.Environment = validatorControlIntent, nil, nil
	c.Anchor, c.Prefix, c.Records, c.Bytes = types.Hash{1}, types.Hash{2}, 3, 100
	c.InputRecord, c.InputKind = 2, inputlog.KindNewHead
	c.Head, _ = codec.EncodeHeader(lower.Header)
	c.Before = append([]uint64(nil), seed.After...)
	c.After = r.core.TimerGenerations()
	c.BeforeView, c.AfterView = validatorHistoryAdoption(r.core), validatorHistoryAdoption(r.core)
	c.Wait, _ = validatorHistoryWaitBytes(r.core.ValidatorStartWait())
	c.Outputs, _ = inputlog.OutDigest(outs)
	if _, err := encodeValidatorHistoryControl(walValidatorIntent, c); err != nil {
		t.Fatal("shape decoder confused current EnvHead with retained target", err)
	}
}

func TestValidatorStartProfileDistinguishesHeightCompletion(t *testing.T) {
	seed, r := historySeedModel(t, false)
	c := seed
	c.Mode, c.Options, c.Environment = validatorControlComplete, nil, nil
	c.Anchor, c.Prefix, c.Records, c.Bytes = types.Hash{1}, types.Hash{2}, 4, 200
	c.InputRecord, c.InputKind = 2, inputlog.KindNewHead
	c.Before, c.BeforeView = r.core.TimerGenerations(), validatorHistoryAdoption(r.core)
	next := block(t, 10, 1, types.Address{}, types.Hash{})
	r.env.head = next.Header
	r.core.Step(r.env, consensus.NewHead{Header: next.Header})
	c.Head, _ = codec.EncodeHeader(next.Header)
	c.After, c.AfterView = r.core.TimerGenerations(), validatorHistoryAdoption(r.core)
	if _, err := encodeValidatorHistoryControl(walEndHeight, c); err != nil {
		t.Fatal("actual adopted-height completion rejected", err)
	}
	if _, err := encodeValidatorHistoryControl(walValidatorComplete, c); err == nil {
		t.Fatal("height transition lost its actual boundary")
	}
	c.BeforeView = validatorHistoryView{}
	if _, err := encodeValidatorHistoryControl(walEndHeight, c); err == nil {
		t.Fatal("first adoption pretended to finish an old height")
	}
	if _, err := encodeValidatorHistoryControl(walValidatorComplete, c); err != nil {
		t.Fatal("first adoption completion rejected", err)
	}
}

func TestValidatorStartProfileWitnessPreservesAvailabilityAndKeys(t *testing.T) {
	set, err := validator.NewSet([]types.Address{{1}, {2}}, [][]byte{nil, {}}, types.ProposerPolicy{ID: types.Sticky})
	if err != nil {
		t.Fatal(err)
	}
	w, err := validatorHistoryWitness(inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: types.HeightFromUint64(10), Key: types.Hash{7}, Validators: set})
	if err != nil {
		t.Fatal(err)
	}
	call, err := w.call()
	if err != nil || call.Validators.At(0).BLSPublicKey != nil || call.Validators.At(1).BLSPublicKey == nil || call.Validators.Policy().ID != types.Sticky {
		t.Fatal("ordered nil-key witness lost", err)
	}
	empty, err := validator.NewSet(nil, nil, types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []*validator.Set{nil, empty} {
		w, err := validatorHistoryWitness(inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Validators: original})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := w.call()
		if err != nil || (decoded.Validators == nil) != (original == nil) {
			t.Fatal("unavailable and valid empty conflated", err)
		}
	}
	w.Keys[0] = 2
	if _, err := w.call(); err == nil {
		t.Fatal("nonboolean presence witness accepted")
	}
}

func TestValidatorStartProfileOptionsIncludePrivateConfiguration(t *testing.T) {
	policy := uint64(0)
	makeConfig := func(timeout uint64, transitions []types.Transition) *types.Config {
		return types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: timeout, BlockPeriodSeconds: 1, EpochLength: 4, ProposerPolicy: &policy}, transitions, types.GenesisInit{}, big.NewInt(1))
	}
	base := Config{Core: consensus.Options{Improvements: consensus.ImprovementSet(0).With(consensus.DeferValidatorStart), Config: makeConfig(2, nil)}, ReplayWAL: true}
	original, err := validatorHistoryOptionsBytes(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []*types.Config{nil, makeConfig(3, nil), makeConfig(2, []types.Transition{{Block: big.NewInt(10), WBFT: &types.WBFTParams{EpochLength: 8}}})} {
		cfg := base
		cfg.Core.Config = changed
		encoded, err := validatorHistoryOptionsBytes(cfg)
		if err != nil || bytes.Equal(original, encoded) {
			t.Fatal("effective private configuration omitted", err)
		}
	}
	var ruleBytes [][]byte
	for _, activation := range []string{"10", "11"} {
		cfg := base
		cfg.Core.Config, err = types.ParseChainConfig([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"rejectNumberJump":` + activation + `}}}`))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := validatorHistoryOptionsBytes(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ruleBytes = append(ruleBytes, encoded)
	}
	if bytes.Equal(ruleBytes[0], ruleBytes[1]) {
		t.Fatal("rule activations/digest omitted")
	}
	off := base
	off.Core.Improvements = 0
	if _, err := validatorHistoryOptionsBytes(off); err == nil {
		t.Fatal("profile selected by configuration data alone")
	}
}

func TestValidatorStartProfileHaltIsBoundedAndSeparate(t *testing.T) {
	halt := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlHalt, HaltReason: validatorHaltLimit,
		Anchor: types.Hash{1}, Prefix: types.Hash{2}, Records: math.MaxInt64, Bytes: math.MaxInt64}
	record, err := encodeValidatorHistoryControl(walValidatorHalt, halt)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wal.Encode(record)
	if err != nil || uint64(len(frame)) > validatorHistoryHaltBytes {
		t.Fatal("terminal control exceeds its reserved complete frame", len(frame), err)
	}
	decoded, err := decodeValidatorHistoryControl(record)
	if err != nil || decoded.Mode != validatorControlHalt {
		t.Fatal("terminal halt shape lost", err)
	}
	if _, err := encodeValidatorHistoryControl(walValidatorComplete, halt); err == nil {
		t.Fatal("halt was accepted as a completion")
	}
	seed, _ := historySeedModel(t, false)
	for _, change := range []func(*validatorHistoryControl){
		func(c *validatorHistoryControl) { c.Version++ },
		func(c *validatorHistoryControl) { c.Before = c.Before[:4] },
		func(c *validatorHistoryControl) { c.InnerFormat = 9 },
		func(c *validatorHistoryControl) { c.BeforeView.Adopted = 2 },
		func(c *validatorHistoryControl) { c.Mode = 99 },
	} {
		model := seed
		change(&model)
		if _, err := encodeValidatorHistoryControl(walRunStart, model); err == nil {
			t.Fatal("unsupported offline control shape accepted")
		}
	}
}
