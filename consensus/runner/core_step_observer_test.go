package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type coreObservations struct {
	steps         []CoreStepObservation
	inspect       func()
	alterDetached bool
	writer        journal.Writer
}

func (o *coreObservations) ObserveCoreStep(s CoreStepObservation) {
	if o.inspect != nil {
		o.inspect()
	}
	copy := s
	copy.Head = bytes.Clone(s.Head)
	copy.Input = bytes.Clone(s.Input)
	copy.Outputs = bytes.Clone(s.Outputs)
	if len(s.Environment) > 0 {
		copy.Environment = make([]CoreEnvObservation, len(s.Environment))
	}
	for i, e := range s.Environment {
		copy.Environment[i] = CoreEnvObservation{Bytes: bytes.Clone(e.Bytes), ValidatorKeyPresent: append([]bool(nil), e.ValidatorKeyPresent...)}
	}
	o.steps = append(o.steps, copy)
	if o.writer != nil {
		o.writer.Put(journal.Record{Body: &copy})
	}
	if o.alterDetached {
		// Only observer-owned serialized copies change, never network frames,
		// signatures, live state or the functional journal's buffers.
		if len(s.Input) > 0 {
			s.Input[0] ^= 1
		}
		if len(s.Outputs) > 0 {
			s.Outputs[0] ^= 1
		}
		if len(s.Head) > 0 {
			s.Head[0] ^= 1
		}
		for _, e := range s.Environment {
			if len(e.Bytes) > 0 {
				e.Bytes[0] ^= 1
			}
		}
	}
}

func coreObservedCalls(t *testing.T, observed []CoreEnvObservation) []inputlog.EnvCall {
	t.Helper()
	var calls []inputlog.EnvCall
	for _, e := range observed {
		c, err := inputlog.DecodeEnv(e.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if c.Kind == inputlog.EnvValidatorsAt && c.Validators != nil {
			if len(e.ValidatorKeyPresent) != c.Validators.Len() {
				t.Fatal("ordered key-presence witness missing")
			}
			keys := make([][]byte, c.Validators.Len())
			for i, present := range e.ValidatorKeyPresent {
				key := c.Validators.At(i).BLSPublicKey
				if present {
					keys[i] = append([]byte{}, key...)
				} else if len(key) != 0 {
					t.Fatal("absent key has bytes")
				}
			}
			c.Validators, err = validator.NewSet(c.Validators.Addresses(), keys, c.Validators.Policy())
			if err != nil {
				t.Fatal(err)
			}
		}
		calls = append(calls, c)
	}
	return calls
}

func TestCoreStepObserverActualAcceptedSource(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.noJournal = true
	observed := new(coreObservations)
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	writer, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/core-source", Synchronous: true}, journal.Identity{Run: "diagnostic-core-source", Self: n.opts.Self, Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit)}})
	if err != nil {
		t.Fatal(err)
	}
	observed.writer = writer
	n.coreSteps = observed
	observed.inspect = func() { _ = n.r.Vars() }
	receive := &runnerReceiveTransitions{writer: writer, clock: n.clock}
	n.receiveCache = &transport.ReceiveLedgerOptions{Pending: 16, PerPeer: 4, KeyWithCode: true, Trace: receive}
	n.boot()
	if n.r.d.Journal != nil {
		t.Fatal("diagnostic observer activated functional journal")
	}
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	n.deliver(0, codec.CodePreprepare, k.preprepare(t, 0, view(10, 0), b))
	raw := k.vote(t, 0, codec.CodePrepare, view(10, 0), b)
	in := transportInbound(k, 0, codec.CodePrepare, raw, n.clock.now)
	in.Stream = transport.NewWriteSession()
	in.Stream.BindObservationRun("original-core-input")
	in.Capture = 1
	in.Origin = transport.ReceiveOrigin{WriterRun: "original-core-input", CaptureID: 1}
	if !n.r.Receiver().Offer(in) {
		t.Fatal("normal signed input refused")
	}
	n.r.Pump()
	n.deliver(2, codec.CodePrepare, k.vote(t, 2, codec.CodePrepare, view(10, 0), b))
	var source transport.ReceiveAcceptSource
	var acceptedLedger, acceptedScope uint64
	for _, r := range receive.snapshot() {
		if r.Action == transport.ReceiveCheckAccept && r.Input.PayloadSHA256 == types.Hash(sha256.Sum256(raw)) && r.Decision == transport.ReceiveRegistered {
			source = r.Source
			acceptedLedger, acceptedScope = r.Ledger, r.Scope
		}
	}
	if source.Step == 0 || source.Output == 0 {
		t.Fatal("actual core ACCEPT not observed")
	}
	// Execute a fresh core from the detached actual input/environment transcript.
	// No receive/cache mutation trace is fed to this core.
	core := consensus.NewState(n.opts)
	matches := 0
	for i, s := range observed.steps {
		if s.Unavailable != "" || s.Step != uint64(i+1) || s.EngineRun != 1 || s.ReplayedPrefix {
			t.Fatal("actual source discontinuity", s.Step, s.Unavailable)
		}
		head, err := codec.DecodeHeader(s.Head)
		if err != nil || codec.BlockHash(head) != codec.BlockHash(n.chain.head) || s.CoreSelf != n.opts.Self || s.Improvements != uint64(n.opts.Improvements) || s.BacklogLimit != int64(n.opts.BacklogLimit) {
			t.Fatal("actual core head/options were substituted", err)
		}
		input, err := inputlog.Decode(s.InputKind, s.Input, nil)
		if err != nil {
			t.Fatal(err)
		}
		env := &replayEnv{head: n.chain.head, answers: coreObservedCalls(t, s.Environment)}
		before, known := receiveContextMetadata(core.Snapshot())
		if known != s.BeforeKnown || before != s.Before {
			t.Fatal("actual pre-step authority/context changed")
		}
		outputs := core.Step(env, input)
		if env.err != nil || len(env.answers) != 0 {
			t.Fatal("actual environment transcript was not consumed exactly", env.err, len(env.answers))
		}
		encoded, err := inputlog.EncodeOutputs(outputs)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := inputlog.OutDigest(outputs)
		if err != nil || !bytes.Equal(encoded, s.Outputs) || digest != s.OutDigest {
			t.Fatal("independent core outputs differ", s.Step, err)
		}
		after, known := receiveContextMetadata(core.Snapshot())
		if known != s.AfterKnown || after != s.After {
			t.Fatal("actual post-step authority/context changed")
		}
		if s.Step == source.Step {
			if s.ReceiveLedgerRun != writer.CaptureRun() || s.ReceiveLedger != acceptedLedger || s.ReceiveScopeBefore != acceptedScope || s.ReceiveScopeBefore == 0 {
				t.Fatal("actual entry scope was replaced by later context")
			}
			if s.Origin != in.Origin || s.StreamRun != in.Stream.ObservationRun() || s.Stream != in.Stream.ObservationID() {
				t.Fatal("original input provenance replaced")
			}
			if source.Output > uint64(len(outputs)) {
				t.Fatal("actual output cursor unavailable")
			}
			o, ok := outputs[source.Output-1].(consensus.Outcome)
			if !ok || !o.Relayed || o.Peer != in.Peer || uint64(o.Code) != in.Code || o.DedupKey != codec.DedupKey(raw) || o.Via != source.Via {
				t.Fatal("receive registration did not name actual recomputed ACCEPT", o)
			}
			matches++
		}
	}
	if matches != 1 || !reflect.DeepEqual(core.Vars(), n.r.Vars()) {
		t.Fatal("actual core transcript incomplete", matches)
	}
	// Normal Stop/Start may restore a WAL prefix. Newly observed steps must
	// label that prefix, never claim it was a newly observed Start transcript.
	if err := n.r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
		t.Fatal(err)
	}
	n.r.Pump()
	if !n.r.LastReplay().Replayed {
		t.Fatal("normal WAL prefix was not restored")
	}
	n.deliver(2, codec.CodeRoundChange, k.sign(t, 2, &codec.Message{Code: codec.CodeRoundChange, View: view(10, 1)}, nil))
	marked := false
	for _, s := range observed.steps {
		if s.EngineRun == 2 {
			if !s.ReplayedPrefix {
				t.Fatal("restored prefix was presented as complete live evidence")
			}
			marked = true
		}
	}
	if !marked {
		t.Fatal("normal post-restart live step missing")
	}
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(n.jfs, "/core-source")
	if err != nil {
		t.Fatal(err)
	}
	stored := 0
	for _, record := range records {
		if source, ok := record.Body.(*journal.CoreStepRec); ok {
			if record.Kind != journal.KindCoreStep || stored >= len(observed.steps) || !reflect.DeepEqual(*source, observed.steps[stored]) {
				t.Fatal("actual core source changed during durable round trip", stored)
			}
			stored++
		}
	}
	if stored != len(observed.steps) {
		t.Fatal("actual core source records missing", stored, len(observed.steps))
	}
	stops := map[uint64]int{}
	for _, s := range observed.steps {
		if s.InputKind == inputlog.KindStop {
			stops[s.EngineRun]++
			if s.AfterKnown || s.ReceiveScopeAfter != 0 {
				t.Fatal("lifecycle end retained a current context")
			}
		}
	}
	if stops[1] != 1 || stops[2] != 1 {
		t.Fatal("actual lifecycle Stop steps were not observed exactly once", stops)
	}
	var firstEngine []journal.Record
	steps := uint64(0)
	for _, record := range records {
		if s, ok := record.Body.(*journal.CoreStepRec); ok {
			if s.EngineRun != 1 {
				continue
			}
			steps++
		}
		firstEngine = append(firstEngine, record)
	}
	limits := journal.CoreSourceLimits{Records: 10000, Runs: 4, Steps: 1000, Environments: 1000, Outputs: 10000, Bytes: 64 << 20}
	check, err := journal.CheckCoreStepSources(firstEngine, limits)
	if err != nil || check.Status != "consistent" || check.Runs != 1 || check.Steps != steps || check.Accepted == 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
		t.Fatal("durable actual core transcript did not reconstruct independently", check, err)
	}
	check, err = journal.CheckCoreStepSources(records, limits)
	if err != nil || check.Status != "unavailable" || check.Reason != "restored_prefix_not_reconstructed" {
		t.Fatal("restored prefix was promoted to a complete transcript", check, err)
	}
	// These inspections alter only copied offline metadata, never live inputs,
	// packets, signatures, runner state or execution commands.
	for _, test := range []struct {
		name    string
		rewrite func(journal.Record) (journal.Record, bool)
		status  string
	}{
		{"missing_start", func(r journal.Record) (journal.Record, bool) {
			s, ok := r.Body.(*journal.CoreStepRec)
			return r, !ok || s.Step != 1
		}, "unavailable"},
		{"missing_head", func(r journal.Record) (journal.Record, bool) {
			if s, ok := r.Body.(*journal.CoreStepRec); ok {
				c := *s
				c.Head = nil
				r.Body = &c
			}
			return r, true
		}, "unavailable"},
		{"different_declared_self", func(r journal.Record) (journal.Record, bool) {
			if s, ok := r.Body.(*journal.CoreStepRec); ok {
				c := *s
				c.CoreSelf[0] ^= 1
				r.Body = &c
			}
			return r, true
		}, "inconsistent"},
		{"different_recorded_context", func(r journal.Record) (journal.Record, bool) {
			if s, ok := r.Body.(*journal.CoreStepRec); ok && s.Step == 1 {
				c := *s
				c.After.State = "Committed"
				r.Body = &c
			}
			return r, true
		}, "inconsistent"},
		{"extra_environment_answer", func(r journal.Record) (journal.Record, bool) {
			if s, ok := r.Body.(*journal.CoreStepRec); ok && len(s.Environment) > 0 {
				c := *s
				c.Environment = append(append([]journal.CoreEnvObservation(nil), s.Environment...), s.Environment[0])
				r.Body = &c
			}
			return r, true
		}, "inconsistent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var copy []journal.Record
			for _, r := range firstEngine {
				if changed, keep := test.rewrite(r); keep {
					copy = append(copy, changed)
				}
			}
			check, err := journal.CheckCoreStepSources(copy, limits)
			if check.Status != test.status || (err != nil) != (test.status == "inconsistent") || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
				t.Fatal(check, err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		limits journal.CoreSourceLimits
		reason string
	}{
		{"records", journal.CoreSourceLimits{Records: 1, Runs: 4, Steps: 1000, Environments: 1000, Outputs: 10000, Bytes: 64 << 20}, "record_limit"},
		{"steps", journal.CoreSourceLimits{Records: 10000, Runs: 4, Steps: 1, Environments: 1000, Outputs: 10000, Bytes: 64 << 20}, "step_limit"},
		{"bytes", journal.CoreSourceLimits{Records: 10000, Runs: 4, Steps: 1000, Environments: 1000, Outputs: 10000, Bytes: 1}, "source_byte_limit"},
		{"required", journal.CoreSourceLimits{}, "inspection_limits_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			check, err := journal.CheckCoreStepSources(firstEngine, test.limits)
			if err != nil || check.Status != "unavailable" || check.Reason != test.reason {
				t.Fatal(check, err)
			}
		})
	}
	var repeated []journal.Record
	for _, r := range firstEngine {
		repeated = append(repeated, r)
		if s, ok := r.Body.(*journal.CoreStepRec); ok && s.Step == 1 {
			repeated = append(repeated, r)
		}
	}
	check, err = journal.CheckCoreStepSources(repeated, limits)
	if err == nil || check.Status != "inconsistent" || check.Reason != "core_step_repeated_or_exhausted" {
		t.Fatal("duplicate retained step was treated as missing evidence", check, err)
	}
}

func TestCoreStepObserverDetachedValuesPreserveFunctionalRecords(t *testing.T) {
	k := newKeys(t, 4)
	var referenceVars *consensus.Vars
	var referenceWAL []wal.Record
	var referenceSteps []journal.Record
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, k, 1)
		observed := &coreObservations{alterDetached: true}
		if enabled {
			n.coreSteps = observed
		}
		n.boot()
		b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
		reachPrepared(t, n, b)
		records, _, err := wal.ReadAll(n.fs, "/wal")
		if err != nil {
			t.Fatal(err)
		}
		journalRecords, err := journal.ReadAll(n.jfs, "/j")
		if err != nil {
			t.Fatal(err)
		}
		var steps []journal.Record
		for _, r := range journalRecords {
			if _, ok := r.Body.(*journal.StepRec); ok {
				steps = append(steps, r)
			}
		}
		if !enabled {
			referenceVars, referenceWAL, referenceSteps = n.r.Vars(), records, steps
		} else {
			if len(observed.steps) < 5 || !reflect.DeepEqual(referenceVars, n.r.Vars()) || !reflect.DeepEqual(referenceWAL, records) || !reflect.DeepEqual(referenceSteps, steps) {
				t.Fatal("observer-owned value alteration changed functional state or records")
			}
		}
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoreStepObserverEnvironmentPreservesNilKeyPresence(t *testing.T) {
	vs, err := validator.NewSet([]types.Address{{1}, {2}}, [][]byte{nil, {}}, types.ProposerPolicy{ID: types.Sticky})
	if err != nil {
		t.Fatal(err)
	}
	e, err := observeCoreEnvironment(inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: types.HeightFromUint64(10), Validators: vs})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.ValidatorKeyPresent, []bool{false, true}) {
		t.Fatal("nil and empty key presence conflated")
	}
	decoded := coreObservedCalls(t, []CoreEnvObservation{e})[0].Validators
	a, err := receiveAuthorityDigest(vs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := receiveAuthorityDigest(decoded)
	if err != nil || a != b {
		t.Fatal("ordered authority meaning changed", err)
	}
}
