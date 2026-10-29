package runner

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// This fixture computes detached normal core steps and record arrays. It
// creates no signed traffic and never mutates bytes of an existing WAL.
type validatorHistoryModel struct {
	t      *testing.T
	r      *Runner
	frames []wal.Record
	p      validatorHistoryReplay
}

func newValidatorHistoryModel(t *testing.T, pending bool) *validatorHistoryModel {
	t.Helper()
	c, r := historySeedModel(t, pending)
	m := &validatorHistoryModel{t: t, r: r}
	m.inner(walRunStart, &c)
	rec, err := encodeValidatorHistoryControl(walRunStart, c)
	if err != nil {
		t.Fatal(err)
	}
	m.p.anchor, err = validatorHistoryRecordHash(rec)
	if err != nil {
		t.Fatal(err)
	}
	m.append(rec)
	return m
}

func (m *validatorHistoryModel) inner(kind uint8, c *validatorHistoryControl) {
	m.t.Helper()
	inner, err := validatorHistoryInner(m.r.cfg, kind, *c, m.r.core, nil)
	if err != nil {
		m.t.Fatal(err)
	}
	c.InnerFormat, c.Inner = uint64(inner.Format), inner.Body
}

func (m *validatorHistoryModel) append(rec wal.Record) {
	m.t.Helper()
	m.frames = append(m.frames, rec)
	if err := m.p.advance(rec); err != nil {
		m.t.Fatal(err)
	}
}

func (m *validatorHistoryModel) reference(c *validatorHistoryControl) {
	c.Anchor, c.Prefix, c.Bytes, c.Records = m.p.anchor, m.p.prefix, m.p.bytes, m.p.records
}

func (m *validatorHistoryModel) step(in consensus.Input) {
	m.t.Helper()
	body, err := inputlog.Encode(in)
	if err != nil {
		m.t.Fatal(err)
	}
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlIntent,
		Before: m.r.core.TimerGenerations(), BeforeView: validatorHistoryAdoption(m.r.core),
		InputKind: inputlog.Kind(in), InputRecord: uint64(len(m.frames)) + 1}
	c.InputHash, err = validatorHistoryInputHash(c.InputKind, body)
	if err != nil {
		m.t.Fatal(err)
	}
	m.append(encodeInput(c.InputKind, body))
	if nh, ok := in.(consensus.NewHead); ok {
		m.r.env.head = nh.Header
	}
	c.Head = validatorHistoryHeadBytes(m.r.env.head)
	m.r.env.begin(false)
	outs := m.r.core.Step(m.r.env, in)
	for _, answer := range m.r.env.end() {
		w, err := validatorHistoryWitness(answer.call)
		if err != nil {
			m.t.Fatal(err)
		}
		c.Environment = append(c.Environment, w)
		m.append(encodeEnv(w.Bytes))
	}
	c.After, c.AfterView = m.r.core.TimerGenerations(), validatorHistoryAdoption(m.r.core)
	c.Wait, err = validatorHistoryWaitBytes(m.r.core.ValidatorStartWait())
	if err != nil {
		m.t.Fatal(err)
	}
	c.Outputs, err = inputlog.OutDigest(outs)
	if err != nil {
		m.t.Fatal(err)
	}
	m.reference(&c)
	rec, err := encodeValidatorHistoryControl(walValidatorIntent, c)
	if err != nil {
		m.t.Fatal(err)
	}
	m.append(rec)
	for _, out := range outs {
		switch out.(type) {
		case consensus.Broadcast, consensus.Commit, consensus.Relay, consensus.Schedule:
			m.t.Fatal("metadata fixture unexpectedly needs an external effect")
		}
	}
	c.Mode, c.Environment = validatorControlComplete, nil
	m.reference(&c)
	kind := walValidatorComplete
	before, _ := c.BeforeView.value()
	after, _ := c.AfterView.value()
	if c.BeforeView.Adopted == 1 && c.AfterView.Adopted == 1 && after.Sequence.Cmp(before.Sequence) > 0 {
		kind = walEndHeight
	}
	m.inner(kind, &c)
	rec, err = encodeValidatorHistoryControl(kind, c)
	if err != nil {
		m.t.Fatal(err)
	}
	m.append(rec)
}

func (m *validatorHistoryModel) resume() {
	m.t.Helper()
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlResume,
		Head: validatorHistoryHeadBytes(m.r.env.head), Before: m.r.core.TimerGenerations(), After: m.r.core.TimerGenerations(),
		BeforeView: validatorHistoryAdoption(m.r.core), AfterView: validatorHistoryAdoption(m.r.core)}
	var err error
	c.Wait, err = validatorHistoryWaitBytes(m.r.core.ValidatorStartWait())
	if err != nil {
		m.t.Fatal(err)
	}
	m.reference(&c)
	m.inner(walRunStart, &c)
	rec, err := encodeValidatorHistoryControl(walRunStart, c)
	if err != nil {
		m.t.Fatal(err)
	}
	m.append(rec)
}

func (m *validatorHistoryModel) parse() *validatorHistoryReplay {
	m.t.Helper()
	p, err := parseValidatorHistory(m.r.cfg, m.frames, nil)
	if err != nil {
		m.t.Fatal(err)
	}
	if !slices.Equal(p.core.TimerGenerations(), m.r.core.TimerGenerations()) ||
		!sameValidatorHistoryView(validatorHistoryAdoption(p.core), validatorHistoryAdoption(m.r.core)) ||
		p.prefix != m.p.prefix || p.bytes != m.p.bytes || p.records != m.p.records ||
		!bytes.Equal(validatorHistoryHeadBytes(p.head), validatorHistoryHeadBytes(m.r.env.head)) {
		m.t.Fatal("full-prefix reconstruction differs")
	}
	return p
}

func TestValidatorStartHistorySeedOnlyAndResume(t *testing.T) {
	for _, pending := range []bool{false, true} {
		m := newValidatorHistoryModel(t, pending)
		p := m.parse()
		if p.steps != 0 || (p.core.ValidatorStartWait() != nil) != pending {
			t.Fatal("seed-only state missing")
		}
		if pending && (p.timers[4] == nil || p.timers[0] != nil) {
			t.Fatal("pending retry-only seed not reconstructed")
		}
		for range 2 {
			m.resume()
			m.parse()
		}
	}
}

func TestValidatorStartHistoryFullPrefixRetainsRecordedHeads(t *testing.T) {
	m := newValidatorHistoryModel(t, false)
	for _, height := range []uint64{10, 11, 12} {
		h := block(t, height, 0, types.Address{}, types.Hash{}).Header
		m.step(consensus.NewHead{Header: h})
		m.resume()
		p := m.parse()
		if p.state.LastEnd == nil || p.state.LastEnd.CmpUint64(height) != 0 || p.steps != height-9 {
			t.Fatal("intermediate height or full prefix discarded")
		}
	}
}

func TestValidatorStartHistoryPendingMismatchedHeadAndFirstAdoption(t *testing.T) {
	m := newValidatorHistoryModel(t, true)
	wait := m.r.core.ValidatorStartWait()
	lower := block(t, 8, 0, types.Address{}, types.Hash{}).Header
	m.step(consensus.NewHead{Header: lower})
	m.resume()
	p := m.parse()
	if p.core.ValidatorStartWait().Target.Cmp(wait.Target) != 0 || p.timers[4] == nil {
		t.Fatal("ignored head replaced pending ownership")
	}
	m.step(consensus.Timeout{Kind: consensus.ValidatorStartTimer, Gen: wait.Generation, View: types.View{Sequence: wait.Target, Round: wait.RequestedRound}})
	p = m.parse()
	if p.core.ValidatorStartWait().Generation != wait.Generation+1 {
		t.Fatal("fired mismatched-head retry was not replaced")
	}
	original, _ := codec.DecodeHeader(m.framesSeed(t).Head)
	m.step(consensus.NewHead{Header: original})
	m.r.d.Chain.(*fakeChain).vs = newKeys(t, 4).vs
	// A different available set is still normal detached availability metadata;
	// choosing a follower keeps this fixture free of signing or builder effects.
	wait = m.r.core.ValidatorStartWait()
	m.step(consensus.Timeout{Kind: consensus.ValidatorStartTimer, Gen: wait.Generation, View: types.View{Sequence: wait.Target, Round: wait.RequestedRound}})
	p = m.parse()
	if p.core.ValidatorStartWait() != nil || p.state.LastEnd != nil {
		t.Fatal("first adoption pretended to complete an old height")
	}
}

func (m *validatorHistoryModel) framesSeed(t *testing.T) validatorHistoryControl {
	t.Helper()
	c, err := decodeValidatorHistoryControl(m.frames[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidatorStartHistoryRejectsIncompleteOrUnownedDetachedRecords(t *testing.T) {
	m := newValidatorHistoryModel(t, false)
	m.step(consensus.NewHead{Header: block(t, 10, 0, types.Address{}, types.Hash{}).Header})
	for end := 2; end < len(m.frames); end++ {
		if _, err := parseValidatorHistory(m.r.cfg, m.frames[:end], nil); err == nil {
			t.Fatalf("incomplete prefix %d accepted", end)
		}
	}
	for _, extra := range []wal.Record{m.frames[0], encodeEnv([]byte{}), encodeOwn(ownRec{Code: 1, Payload: []byte{1}}), {Format: 99, Kind: walInput}} {
		model := append(slices.Clone(m.frames), extra)
		if _, err := parseValidatorHistory(m.r.cfg, model, nil); err == nil {
			t.Fatal("unowned or unknown record accepted")
		}
	}
	for _, field := range []string{"prefix", "anchor", "horizon", "usage", "input", "digest", "generation"} {
		model := slices.Clone(m.frames)
		i := len(model) - 1
		c, err := decodeValidatorHistoryControl(model[i])
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "prefix":
			c.Prefix[0] ^= 1
		case "anchor":
			c.Anchor[0] ^= 1
		case "horizon":
			c.Records++
		case "usage":
			c.Bytes++
		case "input":
			c.InputHash[0] ^= 1
		case "digest":
			c.Outputs[0] ^= 1
		case "generation":
			c.After = slices.Clone(c.After)
			c.After[0]++
		}
		model[i], err = encodeValidatorHistoryControl(model[i].Kind, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseValidatorHistory(m.r.cfg, model, nil); err == nil {
			t.Fatalf("detached %s mismatch accepted", field)
		}
	}
}

func TestValidatorStartHistoryHaltAndBudgetRemainCumulative(t *testing.T) {
	m := newValidatorHistoryModel(t, true)
	m.resume()
	c := validatorHistoryControl{Version: validatorStartVersion, Mode: validatorControlHalt, HaltReason: validatorHaltLimit}
	m.reference(&c)
	rec, err := encodeValidatorHistoryControl(walValidatorHalt, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseValidatorHistory(m.r.cfg, append(slices.Clone(m.frames), rec), nil); !errors.Is(err, errValidatorHistoryBudget) {
		t.Fatal("halt was accepted", err)
	}
	cfg := m.r.cfg
	cfg.ValidatorHistory = &ValidatorHistoryLimits{Bytes: m.p.bytes + validatorHistoryHaltBytes - 1, Records: 100}
	if _, err := parseValidatorHistory(cfg, m.frames, nil); err == nil {
		t.Fatal("restart budget/config was reset")
	}
	for _, positions := range [][]wal.Position{{{Segment: 1, Offset: 0}}, {{Segment: 1, Offset: 1}, {Segment: 1, Offset: 2}}} {
		if _, err := parseValidatorHistory(m.r.cfg, m.frames, positions); err == nil {
			t.Fatal("invalid source positions accepted")
		}
	}
}

func TestValidatorStartHistoryHandshakeChecksBeforeReturningActions(t *testing.T) {
	m := newValidatorHistoryModel(t, false)
	m.step(consensus.NewHead{Header: block(t, 10, 0, types.Address{}, types.Hash{}).Header})
	fs := fsys.NewMem()
	log, _, err := wal.Open(fs, "/history", wal.Options{SegmentBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range m.frames {
		if _, err := log.AppendSync(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := InspectWALForConfig(fs, "/history", m.r.cfg)
	if err != nil || state.LastEnd == nil || state.LastEnd.CmpUint64(10) != 0 {
		t.Fatal("complete profile handshake failed", err)
	}
	if _, err := InspectWAL(fs, "/history"); err == nil {
		t.Fatal("legacy caller silently skipped selected history")
	}
	off := m.r.cfg
	off.Core.Improvements = 0
	if _, err := InspectWALForConfig(fs, "/history", off); err == nil {
		t.Fatal("flag-off handshake accepted selected history")
	}
	noReplay := m.r.cfg
	noReplay.ReplayWAL = false
	if _, err := InspectWALForConfig(fs, "/history", noReplay); err == nil {
		t.Fatal("replay-off handshake accepted selected history")
	}
	// A different fresh in-memory log models an unfinished recording. Nothing
	// stored above is modified or removed to create this negative case.
	partial, _, err := wal.Open(fs, "/unfinished", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range m.frames[:len(m.frames)-1] {
		if _, err := partial.AppendSync(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectWALForConfig(fs, "/unfinished", m.r.cfg); err == nil {
		t.Fatal("handshake exposed incomplete actions")
	}
}

func validatorHistoryModelNext(t *testing.T, limits NextHeightLimits) *validatorHistoryModel {
	t.Helper()
	m := newValidatorHistoryModel(t, false)
	m.r.cfg.NextHeight = &limits
	c := m.framesSeed(t)
	var err error
	c.Options, err = validatorHistoryOptionsBytes(m.r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.inner(walRunStart, &c)
	rec, err := encodeValidatorHistoryControl(walRunStart, c)
	if err != nil {
		t.Fatal(err)
	}
	m.frames = nil
	m.p = validatorHistoryReplay{}
	m.p.anchor, err = validatorHistoryRecordHash(rec)
	if err != nil {
		t.Fatal(err)
	}
	m.append(rec)
	return m
}

func (m *validatorHistoryModel) deferred(kind uint8, d deferredRecord) {
	m.t.Helper()
	body, err := rlp.Encode(d)
	if err != nil {
		m.t.Fatal(err)
	}
	m.append(wal.Record{Format: nextHeightFormat, Kind: kind, Body: body})
}

func TestValidatorStartHistoryDeferredValidatesEveryAdmission(t *testing.T) {
	// Ordinary local signature fixtures are kept in detached record arrays;
	// no transport sends them and no stored signed bytes are altered.
	k := newKeys(t, 4)
	makeRecord := func(id, round uint64) deferredRecord {
		msg := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(round)}}
		return deferredRecord{ID: id, Code: uint64(msg.Code), Payload: k.sign(t, 0, msg, nil), Peer: k.addrs[1]}
	}
	a, b := makeRecord(1, 1), makeRecord(2, 2)
	base := NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}
	tests := []struct {
		name, reason string
		limits       NextHeightLimits
		second       deferredRecord
	}{
		{"entries", "limits", NextHeightLimits{Entries: 1, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}, b},
		{"bytes", "limits", NextHeightLimits{Entries: 4, Bytes: uint64(len(a.Payload) + len(b.Payload) - 1), PerPeer: 4, PerSource: 4}, b},
		{"peer", "peer or source", NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 1, PerSource: 4}, b},
		{"source", "peer or source", NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 4, PerSource: 1}, b},
		{"slot", "slot", base, func() deferredRecord { d := a; d.ID = 2; return d }()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validatorHistoryModelNext(t, tc.limits)
			m.deferred(walDeferredAdmit, a)
			p := m.parse()
			if len(p.pending) != 1 || p.lastAdmission != 1 {
				t.Fatal("valid positive reservation was lost")
			}
			m.deferred(walDeferredAdmit, tc.second)
			// Eventual releases cannot erase an invalid earlier quota crossing.
			m.deferred(walDeferredDrop, a)
			m.deferred(walDeferredDrop, tc.second)
			if _, err := parseValidatorHistory(m.r.cfg, m.frames, nil); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatal("historical invalid admission was not rejected", err)
			}
		})
	}
	m := validatorHistoryModelNext(t, base)
	m.deferred(walDeferredAdmit, a)
	m.deferred(walDeferredDrop, a)
	m.resume()
	m.deferred(walDeferredAdmit, b)
	p := m.parse()
	if len(p.pending) != 1 || p.pending[0].ID != 2 || p.lastAdmission != 2 {
		t.Fatal("retained ID/high-water order changed")
	}
	m.deferred(walDeferredDrop, b)
	m.deferred(walDeferredAdmit, a)
	if _, err := parseValidatorHistory(m.r.cfg, m.frames, nil); err == nil {
		t.Fatal("consumed admission ID reused after restart")
	}
	bad := validatorHistoryModelNext(t, base)
	bad.deferred(walDeferredAdmit, deferredRecord{ID: 1, Code: uint64(codec.CodeRoundChange), Payload: []byte{0}})
	if _, err := parseValidatorHistory(bad.r.cfg, bad.frames, nil); err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatal("unrecoverable detached envelope accepted", err)
	}
}
