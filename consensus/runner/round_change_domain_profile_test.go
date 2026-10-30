package runner

import (
	"bytes"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

// This constructs unsigned, detached control models. It neither changes a
// stored signed history nor delivers packets to a running validator.
func domainHistorySeedModel(t *testing.T, flags consensus.ImprovementSet) (validatorHistoryControl, Config) {
	t.Helper()
	k := newKeys(t, 4)
	chainConfig, err := types.ParseChainConfig([]byte(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":10}}}`))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := types.DomainForConfig(chainConfig, types.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	head := block(t, 9, 0, k.addrs[3], types.Hash{})
	chain := &fakeChain{head: head.Header, vs: k.vs, clock: &manualClock{}}
	cfg := Config{Core: consensus.Options{Config: chainConfig, Self: k.addrs[1], Improvements: flags, RoundChangeDomain: domain}, ReplayWAL: true}
	r := &Runner{cfg: cfg, d: Deps{Chain: chain}}
	r.core, err = consensus.NewStateChecked(cfg.Core)
	if err != nil {
		t.Fatal(err)
	}
	r.env = &liveEnv{r: r, head: head.Header}
	c := validatorHistoryControl{Version: roundChangeDomainVersion, Mode: validatorControlSeed,
		Before: r.core.TimerGenerations(), BeforeView: validatorHistoryAdoption(r.core), InputKind: inputlog.KindStart}
	c.Options, err = validatorHistoryOptionsBytes(cfg)
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
		witness, err := validatorHistoryWitness(answer.call)
		if err != nil {
			t.Fatal(err)
		}
		c.Environment = append(c.Environment, witness)
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
	inner, err := validatorHistoryInner(cfg, walRunStart, c, r.core, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.InnerFormat, c.Inner = uint64(inner.Format), inner.Body
	return c, cfg
}

func TestRoundChangeDomainFunctionalControlsKeepActualTimerWidth(t *testing.T) {
	for _, test := range []struct {
		flags consensus.ImprovementSet
		width int
	}{{0, 3}, {consensus.ImprovementSet(0).With(consensus.ValidateRoundProposals), 4},
		{consensus.ImprovementSet(0).With(consensus.DeferValidatorStart), 5},
		{consensus.ImprovementSet(0).With(consensus.DeferValidatorStart).With(consensus.ValidateRoundProposals), 5}} {
		seed, cfg := domainHistorySeedModel(t, test.flags)
		if len(seed.Before) != test.width || len(seed.After) != test.width {
			t.Fatal("domain forced a local timer slot", test.width)
		}
		record, err := encodeValidatorHistoryControl(walRunStart, seed)
		if err != nil || record.Format != roundChangeDomainFormat {
			t.Fatal("domain seed did not use functional format 6", err)
		}
		decoded, err := decodeValidatorHistoryControl(record)
		if err != nil || decoded.Version != roundChangeDomainVersion {
			t.Fatal(err)
		}
		again, err := encodeValidatorHistoryControl(walRunStart, decoded)
		if err != nil || !bytes.Equal(record.Body, again.Body) {
			t.Fatal("domain control roundtrip was not canonical", err)
		}
		if _, err := parseValidatorHistory(cfg, []wal.Record{record}, nil); err != nil {
			t.Fatal("own complete unsigned seed cannot be reconstructed", test.width, err)
		}
		wrongWidth := seed
		wrongWidth.Before = append(append([]uint64(nil), seed.Before...), 0)
		wrongWidth.After = append(append([]uint64(nil), seed.After...), 0)
		if changed, err := encodeValidatorHistoryControl(walRunStart, wrongWidth); err == nil {
			if _, err := parseValidatorHistory(cfg, []wal.Record{changed}, nil); err == nil {
				t.Fatal("detached model granted a timer slot absent from its options")
			}
		}
		wrongFormat := record
		wrongFormat.Format = validatorStartFormat
		if _, err := parseValidatorHistory(cfg, []wal.Record{wrongFormat}, nil); err == nil {
			t.Fatal("format 5 was accepted as a domain profile")
		}
	}
}

func TestRoundChangeDomainHistoryRepeatedProjectionAndLiveWALRequirement(t *testing.T) {
	_, cfg := domainHistorySeedModel(t, 0)
	first, err := validatorHistoryOptionsBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := freezeValidatorHistoryConfig(&cfg, nil); err != nil || cfg.ValidatorHistory != nil {
			t.Fatal("domain-only default became a user Defer override", err)
		}
		next, err := validatorHistoryOptionsBytes(cfg)
		if err != nil || !bytes.Equal(first, next) {
			t.Fatal("repeated read-only projection changed the profile", err)
		}
	}
	if _, err := New(cfg, Deps{}); err == nil {
		t.Fatal("live domain runner accepted an absent WAL")
	}
	cfg.ValidatorHistory = &ValidatorHistoryLimits{Bytes: 1 << 20, Records: 4096}
	if err := freezeValidatorHistoryConfig(&cfg, nil); err == nil {
		t.Fatal("domain-only runner accepted a public Defer override")
	}
}
