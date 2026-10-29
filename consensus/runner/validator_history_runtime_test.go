package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func closeValidatorHistoryNode(t *testing.T, n *tnode) {
	t.Helper()
	if n.r != nil {
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if n.r.d.Journal != nil {
			if err := n.r.d.Journal.Close(); err != nil {
				t.Fatal(err)
			}
		}
		n.r = nil
	}
	if n.log != nil {
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		n.log = nil
	}
}

func readValidatorHistoryNode(t *testing.T, n *tnode) []wal.Record {
	t.Helper()
	records, _, err := wal.ReadAll(n.fs, "/wal")
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestValidatorStartHistoryRuntimeSeedOnlyBuildAndOrdinaryReopen(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 0)
	n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart)
	n.boot()
	t.Cleanup(func() { closeValidatorHistoryNode(t, n) })
	if len(n.app.builds) != 1 {
		t.Fatal("initial current builder missing")
	}
	records := readValidatorHistoryNode(t, n)
	if len(records) != 1 || records[0].Format != validatorStartFormat || records[0].Kind != walRunStart {
		t.Fatal("seed was not the first complete record")
	}
	if _, err := parseValidatorHistory(n.r.cfg, records, nil); err != nil {
		t.Fatal(err)
	}
	if err := n.r.d.Journal.(*journal.FileWriter).Sync(); err != nil {
		t.Fatal(err)
	}
	jrecs, err := journal.ReadAll(n.jfs, "/j")
	if err != nil {
		t.Fatal(err)
	}
	foundStart := false
	for _, record := range jrecs {
		if step, ok := record.Body.(*journal.StepRec); ok && step.InputKind == "start" {
			foundStart = true
			if len(step.TimerGens) != 5 {
				t.Fatal("actual fresh pre-Start generations missing")
			}
			for _, gen := range step.TimerGens {
				if gen != 0 {
					t.Fatal("fresh journal stored post-Start generations")
				}
			}
		}
	}
	if !foundStart {
		t.Fatal("fresh Start step missing")
	}
	closeValidatorHistoryNode(t, n)
	n.boot()
	if !n.r.LastReplay().Replayed || len(n.app.builds) != 2 {
		t.Fatal("seed-only reopen lost current builder", n.r.LastReplay(), len(n.app.builds))
	}
	for _, height := range []uint64{10, 11} {
		head := block(t, height, 0, k.addrs[3], codec.BlockHash(n.chain.head)).Header
		n.chain.head = head
		n.r.NewHead(head)
		n.r.Pump()
		if err := n.r.Halted(); err != nil {
			t.Fatal(err)
		}
	}
	state, err := InspectWALForConfig(n.fs, "/wal", n.r.cfg)
	if err != nil || state.LastEnd == nil || state.LastEnd.CmpUint64(11) != 0 {
		t.Fatal("normal intermediate heights not complete", err)
	}
	before := n.r.core.TimerGenerations()
	closeValidatorHistoryNode(t, n)
	n.boot()
	for i, gen := range n.r.core.TimerGenerations() {
		if gen != before[i] {
			t.Fatal("ordinary reopen reset a generation")
		}
	}
	if _, err := parseValidatorHistory(n.r.cfg, readValidatorHistoryNode(t, n), nil); err != nil {
		t.Fatal(err)
	}
	if len(n.net.sent) != 0 {
		t.Fatal("head-only lifecycle unexpectedly emitted consensus traffic")
	}
}

func TestValidatorStartHistoryRuntimeNormalVoteReservation(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart)
	n.boot()
	t.Cleanup(func() { closeValidatorHistoryNode(t, n) })
	// This is an ordinary consensus timeout and the builtin FileSigner, with
	// no packet corruption, failure handler or actual network attached.
	n.advance(2 * time.Second)
	if err := n.r.Halted(); err != nil {
		t.Fatal(err)
	}
	if len(n.net.own(codec.CodeRoundChange)) == 0 {
		t.Fatal("normal own vote was not recorded")
	}
	records := readValidatorHistoryNode(t, n)
	p, err := parseValidatorHistory(n.r.cfg, records, nil)
	if err != nil || p.steps == 0 {
		t.Fatal("reserved own vote cannot be reconstructed", err)
	}
	for _, rec := range records {
		if rec.Format == validatorStartFormat && rec.Kind == walValidatorHalt {
			t.Fatal("normal vote consumed terminal reserve")
		}
	}
	closeValidatorHistoryNode(t, n)
	n.boot()
	if !n.r.LastReplay().Replayed || n.r.Halted() != nil {
		t.Fatal("normal vote history did not reopen")
	}
}

func TestValidatorStartHistoryRuntimeBudgetHaltsBeforeNewBuild(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 0)
	n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart)
	// Construct the normal runner with an explicit small experimental cap;
	// the expected resource boundary is not an injected storage failure.
	log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n.log = log
	if err := n.fs.MkdirAll("/pv", 0o700); err != nil {
		t.Fatal(err)
	}
	signer, err := privval.NewKeySigner(n.fs, nil, k.secret[0], "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{Chain: n.chain, App: n.app, WAL: log, Clock: n.clock, Signer: signer}
	cfg := Config{Core: n.opts, ReplayWAL: true, Manual: true, ValidatorHistory: &ValidatorHistoryLimits{Bytes: 1 << 20, Records: 4}}
	n.r, err = New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeValidatorHistoryNode(t, n) })
	if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	builds := len(n.app.builds)
	head := block(t, 10, 0, k.addrs[3], codec.BlockHash(n.chain.head)).Header
	n.chain.head = head
	n.r.NewHead(head)
	n.r.Pump()
	if n.r.Halted() == nil || len(n.app.builds) != builds {
		t.Fatal("unreserved builder ran after history exhaustion")
	}
	records := readValidatorHistoryNode(t, n)
	if len(records) != 2 || records[1].Kind != walValidatorHalt {
		t.Fatal("bounded terminal halt not persisted exactly once", len(records))
	}
	if _, err := InspectWALForConfig(n.fs, "/wal", cfg); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("handshake lost durable budget halt", err)
	}
	_ = n.r.validatorHistory.abort(errValidatorHistoryProfile)
	if len(readValidatorHistoryNode(t, n)) != 2 {
		t.Fatal("second terminal control was appended")
	}
}

func TestValidatorStartHistoryRuntimeRecordedPendingRestoresOnlyRetry(t *testing.T) {
	// Capture a detached pending metadata seed into a fresh normal log. The
	// actual application lookup remains available; no live failure is injected.
	m := newValidatorHistoryModel(t, true)
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.chain.head = m.r.env.head
	n.opts = m.r.cfg.Core
	n.opts.Self = k.addrs[1]
	// Bind this new test's normal signer identity before the first capture.
	c := m.framesSeed(t)
	m.r.cfg.Core.Self = k.addrs[1]
	var err error
	c.Options, err = validatorHistoryOptionsBytes(m.r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	record, err := encodeValidatorHistoryControl(walRunStart, c)
	if err != nil {
		t.Fatal(err)
	}
	log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.AppendSync(record); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	n.boot()
	t.Cleanup(func() { closeValidatorHistoryNode(t, n) })
	if n.r.core.ValidatorStartWait() == nil || len(n.app.builds) != 0 || len(n.net.sent) != 0 {
		t.Fatal("pending restore acquired production outputs")
	}
	n.r.timers.mu.Lock()
	for i, entry := range n.r.timers.live {
		if (entry != nil) != (i == int(consensus.ValidatorStartTimer)) {
			n.r.timers.mu.Unlock()
			t.Fatal("pending restore installed an old timer", i)
		}
	}
	n.r.timers.mu.Unlock()
}

func TestValidatorStartHistoryRuntimeCompoundProfiles(t *testing.T) {
	for _, all := range []bool{false, true} {
		k := newKeys(t, 4)
		n := newTNode(t, k, 1)
		n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart).With(consensus.BindPriorHead).With(consensus.ValidateRoundProposals)
		if all {
			n.opts.Improvements = consensus.KnownImprovements()
		}
		n.opts.RoundChangeRetry = &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
		cfg := Config{Core: n.opts, ReplayWAL: true, Manual: true, NextHeight: &NextHeightLimits{Entries: 8, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}}
		boot := func() {
			if err := n.fs.MkdirAll("/pv", 0o700); err != nil {
				t.Fatal(err)
			}
			signer, err := privval.NewKeySigner(n.fs, nil, k.secret[1], "/pv/state")
			if err != nil {
				t.Fatal(err)
			}
			log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{SegmentBytes: 512, KeepHeights: 1})
			if err != nil {
				t.Fatal(err)
			}
			n.log = log
			n.r, err = New(cfg, Deps{Chain: n.chain, App: n.app, Clock: n.clock, Signer: signer, WAL: log})
			if err != nil {
				t.Fatal(err)
			}
			if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
				t.Fatal(err)
			}
		}
		boot()
		for _, height := range []uint64{10, 11, 12} {
			head := block(t, height, 0, k.addrs[3], codec.BlockHash(n.chain.head)).Header
			n.chain.head = head
			n.r.NewHead(head)
			n.r.Pump()
			if err := n.r.Halted(); err != nil {
				t.Fatal(err)
			}
		}
		before := n.r.core.TimerGenerations()
		p, err := parseValidatorHistory(n.r.cfg, readValidatorHistoryNode(t, n), nil)
		if err != nil || p.state.LastEnd == nil || p.state.LastEnd.CmpUint64(12) != 0 {
			t.Fatal("compound full prefix failed", err)
		}
		closeValidatorHistoryNode(t, n)
		boot()
		if !n.r.LastReplay().Replayed {
			t.Fatal("compound profile did not reopen")
		}
		for i, gen := range n.r.core.TimerGenerations() {
			if gen != before[i] {
				t.Fatal("compound generation reset")
			}
		}
		closeValidatorHistoryNode(t, n)
	}
}

func TestValidatorStartHistoryTerminalFailureIsNotBudgetExhaustion(t *testing.T) {
	m := newValidatorHistoryModel(t, true)
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlHalt, HaltReason: validatorHaltFailure}
	m.reference(&c)
	record, err := encodeValidatorHistoryControl(walValidatorHalt, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseValidatorHistory(m.r.cfg, append(m.frames, record), nil); !errors.Is(err, errValidatorHistoryHalted) || errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("non-budget terminal cause misclassified", err)
	}
	c.HaltReason = 99
	if _, err := encodeValidatorHistoryControl(walValidatorHalt, c); err == nil {
		t.Fatal("unknown terminal cause accepted")
	}
}

type validatorHistoryCountingSigner struct {
	*privval.FileSigner
	calls int
}

func (s *validatorHistoryCountingSigner) SignVote(request privval.VoteRequest) (privval.VoteSignature, error) {
	s.calls++
	return s.FileSigner.SignVote(request)
}

func TestValidatorStartHistoryBudgetPrecedesActualSignerCall(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart)
	if err := n.fs.MkdirAll("/pv", 0o700); err != nil {
		t.Fatal(err)
	}
	actual, err := privval.NewKeySigner(n.fs, nil, k.secret[1], "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	signer := &validatorHistoryCountingSigner{FileSigner: actual}
	log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n.log = log
	cfg := Config{Core: n.opts, ReplayWAL: true, Manual: true, ValidatorHistory: &ValidatorHistoryLimits{Bytes: 1 << 20, Records: 4}}
	n.r, err = New(cfg, Deps{Chain: n.chain, App: n.app, Clock: n.clock, Signer: signer, WAL: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeValidatorHistoryNode(t, n) })
	if err := n.r.Start(context.Background(), types.HeightFromUint64(10)); err != nil {
		t.Fatal(err)
	}
	n.advance(2 * time.Second)
	if n.r.Halted() == nil || signer.calls != 0 {
		t.Fatal("signer called before whole Step reservation", signer.calls)
	}
	if _, signed := actual.LastHeight(); signed {
		t.Fatal("budget boundary changed builtin signer state")
	}
	records := readValidatorHistoryNode(t, n)
	if len(records) != 2 || records[1].Kind != walValidatorHalt {
		t.Fatal("unreserved Step wrote ordinary frames")
	}
	if _, err := InspectWALForConfig(n.fs, "/wal", cfg); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("ordinary reopen lost terminal halt", err)
	}
}

func validatorHistoryFollowerPendingModel(t *testing.T) *validatorHistoryModel {
	t.Helper()
	m := newValidatorHistoryModel(t, true)
	c := m.framesSeed(t)
	m.r.cfg.Core.Self = types.Address{}
	policy := uint64(0)
	m.r.cfg.Core.Config = types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 1 << 40, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)
	m.r.core = consensus.NewState(m.r.cfg.Core)
	c.Before, c.BeforeView = m.r.core.TimerGenerations(), validatorHistoryAdoption(m.r.core)
	m.r.env.begin(false)
	outs := m.r.core.Step(m.r.env, consensus.Start{})
	c.Environment = nil
	for _, answer := range m.r.env.end() {
		w, err := validatorHistoryWitness(answer.call)
		if err != nil {
			t.Fatal(err)
		}
		c.Environment = append(c.Environment, w)
	}
	var err error
	c.Options, err = validatorHistoryOptionsBytes(m.r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.After, c.AfterView = m.r.core.TimerGenerations(), validatorHistoryAdoption(m.r.core)
	c.Wait, err = validatorHistoryWaitBytes(m.r.core.ValidatorStartWait())
	if err != nil {
		t.Fatal(err)
	}
	c.Outputs, err = inputlog.OutDigest(outs)
	if err != nil {
		t.Fatal(err)
	}
	record, err := encodeValidatorHistoryControl(walRunStart, c)
	if err != nil {
		t.Fatal(err)
	}
	m.frames = nil
	m.p = validatorHistoryReplay{}
	m.p.anchor, err = validatorHistoryRecordHash(record)
	if err != nil {
		t.Fatal(err)
	}
	m.append(record)
	return m
}

func TestValidatorStartHistoryCanonicalCatchupRetainsOrReplacesOneArm(t *testing.T) {
	for _, higher := range []bool{false, true} {
		m := validatorHistoryFollowerPendingModel(t)
		original, err := codec.DecodeHeader(m.framesSeed(t).Head)
		if err != nil {
			t.Fatal(err)
		}
		m.step(consensus.NewHead{Header: block(t, 8, 0, types.Address{}, types.Hash{}).Header})
		n := newTNode(t, newKeys(t, 4), 1)
		n.chain.head = original
		if higher {
			n.chain.head = block(t, 10, 0, types.Address{}, types.Hash{}).Header
		}
		log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		n.log = log
		for _, record := range m.frames {
			if _, err := log.AppendSync(record); err != nil {
				t.Fatal(err)
			}
		}
		observed := &timerSourceObservations{}
		cfg := m.r.cfg
		cfg.Manual = true
		n.r, err = New(cfg, Deps{Chain: n.chain, App: n.app, Clock: n.clock, WAL: log, TimerSources: observed})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
		arms := 0
		for _, record := range observed.records {
			if record.Action == "arm" {
				arms++
			}
		}
		if arms != 1 {
			t.Fatal("catchup restored a duplicate or no physical arm", higher, arms)
		}
		if higher {
			if n.r.core.ValidatorStartWait() != nil || n.r.timers.live[consensus.ValidatorStartTimer] != nil || n.r.timers.live[consensus.RoundTimer] == nil {
				t.Fatal("new canonical head restored obsolete retry")
			}
		} else {
			if n.r.core.ValidatorStartWait() == nil || n.r.timers.live[consensus.ValidatorStartTimer] == nil {
				t.Fatal("zero-output catchup stranded its pending retry")
			}
			// The actual chain has always been available. This ordinary expiry
			// resumes recorded metadata without injecting a live lookup failure.
			n.advance(time.Second)
			if n.r.core.ValidatorStartWait() != nil || n.r.Halted() != nil {
				t.Fatal("normal available lookup did not resume")
			}
		}
		if _, err := parseValidatorHistory(n.r.cfg, readValidatorHistoryNode(t, n), nil); err != nil {
			t.Fatal("catchup prefix cannot be replayed", err)
		}
		closeValidatorHistoryNode(t, n)
	}
}

func TestValidatorStartNoJournalReplayKeepsLogicalStepCount(t *testing.T) {
	n := newTNode(t, newKeys(t, 4), 1)
	n.opts.Self = types.Address{}
	n.opts.Improvements = n.opts.Improvements.With(consensus.DeferValidatorStart)
	cfg := Config{Core: n.opts, ReplayWAL: true, Manual: true}
	boot := func() {
		log, _, err := wal.OpenStrict(n.fs, "/wal", wal.Options{})
		if err != nil {
			t.Fatal(err)
		}
		n.log = log
		n.r, err = New(cfg, Deps{Chain: n.chain, App: n.app, Clock: n.clock, WAL: log})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
	}
	boot()
	head := block(t, 10, 0, types.Address{}, codec.BlockHash(n.chain.head)).Header
	n.chain.head = head
	n.r.NewHead(head)
	n.r.Pump()
	before := n.r.step
	if before < 2 {
		t.Fatal("normal logical steps not observed")
	}
	closeValidatorHistoryNode(t, n)
	boot()
	if !n.r.LastReplay().Replayed || n.r.step != before {
		t.Fatal("journal disabled reset logical Step ownership", n.r.step, before)
	}
	closeValidatorHistoryNode(t, n)
}
