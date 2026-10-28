package journal

import (
	"bytes"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type failureInspectionModel struct {
	records []Record
	mono    uint64
}

func (m *failureInspectionModel) CaptureRun() string { return "failure-inspection-model" }
func (m *failureInspectionModel) ObserveReceiveFailure(event transport.ReceiveFailureEvent) {
	m.mono++
	m.records = append(m.records, Record{Body: &ReceiveFailureCacheRec{Version: ReceiveFailureRecordVersion, Transition: event, Mono: time.Duration(m.mono), WallNs: int64(m.mono)}})
}

func receiveFailureInspectionBounds() ReceiveFailureLimits {
	return ReceiveFailureLimits{Caches: 4, Inbox: InboxLimits{Core: CoreSourceLimits{Records: 1000, Runs: 4, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 4 << 20}, Operations: 1000, Entries: 100, Peers: 10, Frames: 100, Bytes: 4 << 20}}
}

// This finite inspection fixture executes a fresh core Start and actual local
// recovery/cache APIs, but constructs its detached queue/frame metadata as a
// model. It is not an integrated runtime diagnostic profile or socket proof.
// All signatures are intact and owned; no frame is transmitted or altered.
func receiveFailureInspectionFixture(t *testing.T, lru bool) []Record {
	t.Helper()
	m := &failureInspectionModel{mono: 2}
	id := ident()
	id.Run = m.CaptureRun()
	id.Core = CoreOptions{ChainConfig: []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`), CachePolicy: failureDeclarationPolicy(), ReceiveFailureCache: &ReceiveFailureCacheOptions{Profile: ReceiveFailureCacheProfile, Entries: 2}}
	config, err := (coreSourceWriter{config: id.Core.ChainConfig}).configuration()
	if err != nil {
		t.Fatal(err)
	}
	state := consensus.NewState(consensus.Options{Config: config})
	head := &types.Header{Number: types.HeightFromUint64(9), Difficulty: big.NewInt(1)}
	vs, err := validator.NewSet([]types.Address{{1}, {2}, {3}, {4}}, make([][]byte, 4), types.ProposerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	answer := inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: types.HeightFromUint64(10), Key: codec.BlockHash(head), Validators: vs}
	env := &coreSourceEnv{head: head, answers: []inputlog.EnvCall{answer}}
	before, knownBefore, err := coreSourceContext(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	outputs := state.Step(env, consensus.Start{})
	if env.err != nil || len(env.answers) != 0 {
		t.Fatal("ordinary core Start did not consume its original authority lookup", env.err)
	}
	input, err := inputlog.Encode(consensus.Start{})
	if err != nil {
		t.Fatal(err)
	}
	encodedOutputs, err := inputlog.EncodeOutputs(outputs)
	if err != nil {
		t.Fatal(err)
	}
	outDigest, err := inputlog.OutDigest(outputs)
	if err != nil {
		t.Fatal(err)
	}
	headBytes, err := codec.EncodeHeader(head)
	if err != nil {
		t.Fatal(err)
	}
	answerBytes, err := inputlog.EncodeEnv(answer)
	if err != nil {
		t.Fatal(err)
	}
	after, knownAfter, err := coreSourceContext(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	step := &CoreStepRec{EngineRun: 1, Step: 1, Via: "engine", InputKind: inputlog.KindStart, Input: input, Outputs: encodedOutputs, OutDigest: outDigest, Head: headBytes, Environment: []CoreEnvObservation{{Bytes: answerBytes, ValidatorKeyPresent: make([]bool, vs.Len())}}, Before: before, BeforeKnown: knownBefore, After: after, AfterKnown: knownAfter, Entry: CoreStepMoment{Mono: 1, WallNs: 1}, Observed: CoreStepMoment{Mono: 2, WallNs: 2}}
	m.records = []Record{{Body: &SegmentRec{Identity: id}}, {Body: step}}
	digest, err := InboxSnapshotDigest(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	source := transport.ReceiveFailureSource{EngineRun: 1, SnapshotStep: 1, SnapshotPhase: transport.ReceiveFailureStart, SnapshotHash: digest}
	cache, err := transport.NewReceiveFailureCache(transport.ReceiveFailureOptions{Entries: 2, Trace: m})
	if err != nil {
		t.Fatal(err)
	}
	scope := transport.NewValidationScope()
	defer scope.Close()
	context := cache.BeginContext(scope, source)
	raws, peers := make([][]byte, 3), make([]types.Address, 3)
	for i := range raws {
		secret := make([]byte, 32)
		secret[31] = byte(i + 5)
		key, err := ecdsa.PrivateKeyFromBytes(secret)
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = ecdsa.Address(key)
		message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.HeightFromUint64(10)}, Digest: types.Hash{9}}
		payload, err := codec.SigningPayload(message, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		message.Signature, err = ecdsa.SignData(payload, key)
		if err != nil {
			t.Fatal(err)
		}
		raws[i], err = codec.EncodeMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		if recovered, err := consensus.Recover(codec.CodePrepare, raws[i], nil); err != nil || recovered.Source != peers[i] {
			t.Fatal("normal owned signature was not independently valid", err)
		}
	}
	var sequence, capture uint64
	var order []types.Address
	seen := map[types.Address]bool{}
	offer := func(which int) {
		t.Helper()
		peer, raw := peers[which], raws[which]
		stream := uint64(which + 1)
		if !seen[peer] {
			seen[peer] = true
			order = append(order, peer)
			m.records = append(m.records, Record{Body: &PeerRec{PeerIdx: uint32(which), Addr: peer, Event: "attached"}}, Record{Body: &SessionRec{Session: &SessionRef{Run: id.Run, Ordinal: stream}, Peer: peer, Event: SessionObserved, Active: true}})
		}
		capture++
		m.records = append(m.records, Record{Body: &MsgRec{Dir: In, PeerIdx: uint32(which), Session: &SessionRef{Run: id.Run, Ordinal: stream}, Capture: capture, Code: uint64(codec.CodePrepare), WireCode: uint64(codec.CodePrepare), Payload: bytes.Clone(raw), Size: uint64(len(raw)), DedupKey: codec.DedupKey(raw), Engine: "running", Offer: "queued"}})
		sequence++
		m.mono++
		appendSource := InboxRec{Version: InboxSourceVersion, Sequence: sequence, Request: sequence, Action: "append", Peer: peer, Code: uint64(codec.CodePrepare), Payload: bytes.Clone(raw), Capture: capture, Origin: transport.ReceiveOrigin{WriterRun: id.Run, CaptureID: capture}, StreamRun: id.Run, Stream: stream, After: 1, BytesAfter: uint64(len(raw)), Order: slices.Clone(order), Mono: m.mono, WallNs: m.mono}
		m.records = append(m.records, Record{Body: &appendSource})
		sequence++
		m.mono++
		dequeue := appendSource
		dequeue.Sequence, dequeue.Action, dequeue.Payload = sequence, "dequeue", nil
		dequeue.Before, dequeue.After, dequeue.BytesBefore, dequeue.BytesAfter = 1, 0, uint64(len(raw)), 0
		dequeue.Manual, dequeue.Candidates, dequeue.Mono, dequeue.WallNs = 1, []types.Address{peer}, m.mono, m.mono
		m.records = append(m.records, Record{Body: &dequeue})
		workerSource := source
		workerSource.WorkerRequest = appendSource.Request
		in := transport.Inbound{Peer: peer, Code: uint64(codec.CodePrepare), Payload: raw}
		hit, ok := cache.Lookup(context, in, workerSource)
		result := appendSource
		result.Payload, result.Before, result.After, result.BytesBefore, result.BytesAfter = nil, 0, 0, 0, 0
		result.SnapshotEngine, result.SnapshotStep, result.SnapshotPhase, result.SnapshotContextHash = 1, 1, "start", digest
		result.Result = "membership"
		if ok {
			sequence++
			m.mono++
			result.Sequence, result.Action, result.Mono, result.WallNs = sequence, "failure_hit", m.mono, m.mono
			m.records = append(m.records, Record{Body: &InboxFailureHitRec{Version: ReceiveFailureRecordVersion, Source: result, Lookup: hit.Lookup, Original: hit.Reference, Class: hit.Class}})
		} else {
			_, failure, err := consensus.RecoverWithFailure(codec.CodePrepare, raw, func(a types.Address, _ types.View) bool { return vs.Contains(a) })
			if err != ecdsa.ErrUnauthorizedAddress || failure != consensus.RecoveryMembership {
				t.Fatal("local model authority mismatch was not a typed membership failure", failure, err)
			}
			if _, stored := cache.Record(context, in, transport.ReceiveMembershipFailure, workerSource); !stored {
				t.Fatal("model failed to retain the original local verification")
			}
			sequence++
			m.mono++
			result.Sequence, result.Action, result.Mono, result.WallNs = sequence, "check", m.mono, m.mono
			m.records = append(m.records, Record{Body: &result})
		}
	}
	if lru {
		for _, which := range []int{0, 1, 0, 2, 1} {
			offer(which)
		}
	} else {
		offer(0)
		offer(0)
	}
	cache.Close()
	return m.records
}

func TestReceiveFailureSourcesIndependentLocalModelAndLRU(t *testing.T) {
	for _, lru := range []bool{false, true} {
		records := receiveFailureInspectionFixture(t, lru)
		check, err := CheckReceiveFailureSources(records, receiveFailureInspectionBounds())
		want := uint64(1)
		if lru {
			want = 4
		}
		if err != nil || check.Status != "consistent" || check.VerifiedFailures != want || check.Stored != want || check.LookupHits != 1 || check.ConsumedFailures != 1 || check.Inbox.Checked != want || check.Inbox.CachedFailures != 1 || check.Retained != 0 || check.PhysicalStatus != "unavailable" || check.ScheduleStatus != "unavailable" {
			t.Fatal("independent finite local model did not reconstruct", lru, check, err)
		}
		legacy, err := CheckCoreStepSources(records, receiveFailureInspectionBounds().Inbox.Core)
		if err != nil || legacy.Status != "unavailable" || legacy.Reason != "receive_failure_source_profile_unavailable" {
			t.Fatal("new checker silently enabled the ordinary source API", legacy, err)
		}
	}
}

func TestReceiveFailureSourcesFiniteHitIsNotCompletedCheck(t *testing.T) {
	records := receiveFailureInspectionFixture(t, false)
	finite := make([]Record, 0, len(records))
	for _, r := range records {
		if _, ok := r.Body.(*InboxFailureHitRec); !ok {
			finite = append(finite, r)
		}
	}
	check, err := CheckReceiveFailureSources(finite, receiveFailureInspectionBounds())
	if err != nil || check.Status != "consistent" || check.LookupHits != 1 || check.ConsumedFailures != 0 || check.Inbox.Checked != 1 || check.Inbox.RetainedChecking != 1 {
		t.Fatal("a cache lookup invented completed inbox consumption", check, err)
	}
}

func TestReceiveFailureSourcesRequireOriginalEvidence(t *testing.T) {
	records := receiveFailureInspectionFixture(t, false)
	// All variations affect detached inspection metadata after local API calls
	// finish. Original input bytes and signatures never change or reach a node.
	for _, mode := range []string{"frame", "dequeue", "namespace", "publication", "context_time", "lookup_time", "record_time", "check_time", "hit_time", "typed_class", "original_ref", "core_output", "hit_action", "unknown_profile", "gap", "budget"} {
		t.Run(mode, func(t *testing.T) {
			copied := slices.Clone(records)
			limits := receiveFailureInspectionBounds()
			want := "inconsistent"
			changed := false
			for i, rec := range copied {
				if changed {
					break
				}
				switch r := rec.Body.(type) {
				case *MsgRec:
					if mode == "frame" {
						copied = slices.Delete(copied, i, i+1)
						changed, want = true, "unavailable"
					}
				case *InboxRec:
					if mode == "dequeue" && r.Action == "dequeue" {
						copied = slices.Delete(copied, i, i+1)
						changed, want = true, "unavailable"
					}
					if mode == "check_time" && r.Action == "check" {
						c := *r
						c.Mono = 0
						copied[i].Body, changed = &c, true
					}
				case *ReceiveFailureCacheRec:
					c := *r
					if mode == "namespace" {
						c.Transition.Run = "other-model"
						changed = true
					}
					if mode == "publication" && c.Transition.Action == "context" {
						c.Transition.Source.SnapshotHash[0] ^= 1
						changed = true
					}
					if mode == "context_time" && c.Transition.Action == "context" || mode == "lookup_time" && c.Transition.Action == "lookup" || mode == "record_time" && c.Transition.Action == "record" {
						c.Mono, changed = 0, true
					}
					if mode == "typed_class" && c.Transition.Action == "record" {
						c.Transition.Class = transport.ReceiveSignatureFailure
						changed = true
					}
					if changed {
						copied[i].Body = &c
					}
				case *CoreStepRec:
					if mode == "core_output" {
						c := *r
						c.OutDigest[0] ^= 1
						copied[i].Body, changed = &c, true
					}
				case *InboxFailureHitRec:
					c := *r
					if mode == "original_ref" {
						c.Original.Sequence--
						changed = true
					}
					if mode == "hit_action" {
						c.Source.Action = "check"
						changed = true
					}
					if mode == "hit_time" {
						c.Source.Mono, changed = 0, true
					}
					if changed {
						copied[i].Body = &c
					}
				case *SegmentRec:
					if mode == "unknown_profile" {
						c, declaration := *r, *r.Core.ReceiveFailureCache
						declaration.Profile++
						c.Core.ReceiveFailureCache = &declaration
						copied[i].Body, changed, want = &c, true, "unavailable"
					}
				}
			}
			if mode == "gap" {
				copied = append(copied, Record{Body: &GapRec{Dropped: 1, ByKind: []KindCount{{Kind: uint64(KindInboxFailureHit), Count: 1}}}})
				changed, want = true, "unavailable"
			}
			if mode == "budget" {
				limits.Inbox.Bytes = 1
				changed, want = true, "unavailable"
			}
			if !changed {
				t.Fatal("metadata case did not apply")
			}
			check, err := CheckReceiveFailureSources(copied, limits)
			if check.Status != want || (err != nil) != (want == "inconsistent") {
				t.Fatal(mode, check, err)
			}
		})
	}
}
