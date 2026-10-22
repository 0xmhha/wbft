package journal

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func minimalCoreSource(t *testing.T) *CoreStepRec {
	t.Helper()
	in, err := inputlog.Encode(consensus.Start{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := inputlog.EncodeOutputs(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := inputlog.OutDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &CoreStepRec{EngineRun: 1, Step: 1, Via: "engine", InputKind: inputlog.KindStart, Input: in, Outputs: out, OutDigest: digest, Entry: CoreStepMoment{Mono: 1, WallNs: 10}, Observed: CoreStepMoment{Mono: 2, WallNs: 9}}
}

func TestCoreStepRecordStrictCodecAndOriginalProvenance(t *testing.T) {
	s := minimalCoreSource(t)
	s.EngineRun, s.Step = ^uint64(0), (1<<53)+1
	s.Origin = transport.ReceiveOrigin{WriterRun: "original-input", CaptureID: ^uint64(0)}
	s.StreamRun, s.Stream = "original-session", ^uint64(0)
	s.CoreSelf, s.Improvements, s.BacklogLimit = types.Address{9}, ^uint64(0), -(1 << 63)
	head, err := codec.EncodeHeader(&types.Header{Number: types.HeightFromUint64(9), Difficulty: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	s.Head = head
	vs, err := validator.NewSet([]types.Address{{1}, {2}}, [][]byte{nil, {}}, types.ProposerPolicy{ID: types.Sticky})
	if err != nil {
		t.Fatal(err)
	}
	env, err := inputlog.EncodeEnv(inputlog.EnvCall{Kind: inputlog.EnvValidatorsAt, Number: types.HeightFromUint64(10), Validators: vs})
	if err != nil {
		t.Fatal(err)
	}
	s.Environment = []CoreEnvObservation{{Bytes: env, ValidatorKeyPresent: []bool{false, true}}}
	raw, err := encodeBody(Record{Body: s}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBody(KindCoreStep, raw)
	if err != nil {
		t.Fatal(err)
	}
	r := decoded.Body.(*CoreStepRec)
	if r.Origin != s.Origin || r.StreamRun != s.StreamRun || r.Stream != s.Stream || r.EngineRun != s.EngineRun || r.Step != s.Step || r.Observed.WallNs != 9 {
		t.Fatal("original coordinates, integer precision or wall regression changed")
	}
	if r.CoreSelf != s.CoreSelf || r.Improvements != s.Improvements || r.BacklogLimit != s.BacklogLimit || !bytes.Equal(r.Head, s.Head) {
		t.Fatal("actual head/options source changed")
	}
	call, err := DecodeCoreEnvironment(r.Environment[0])
	if err != nil {
		t.Fatal(err)
	}
	if call.Validators.Policy().ID != types.Sticky || call.Validators.At(0).Addr != (types.Address{1}) || call.Validators.At(0).BLSPublicKey != nil || call.Validators.At(1).BLSPublicKey == nil {
		t.Fatal("ordered authority/key presence changed")
	}
	again, err := encodeBody(decoded, decoded.JSeq)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("durable source bytes changed", err)
	}
	var wire coreStepRLP
	if err := rlp.DecodeStrict(raw, &wire); err != nil {
		t.Fatal(err)
	}
	// Invalid shapes are offline codec metadata, never packets sent to peers.
	for _, change := range []func(*coreStepRLP){
		func(w *coreStepRLP) { w.Profile++ },
		func(w *coreStepRLP) { w.Flags = 8 },
		func(w *coreStepRLP) { w.EngineRun = 0 },
		func(w *coreStepRLP) { w.Step = 0 },
		func(w *coreStepRLP) { w.Origin.WriterRun = "" },
		func(w *coreStepRLP) { w.Stream = 0 },
		func(w *coreStepRLP) { w.Via = "unknown" },
		func(w *coreStepRLP) { w.Head = []byte{1} },
		func(w *coreStepRLP) { w.OutDigest[0] ^= 1 },
		func(w *coreStepRLP) { w.Before.ValidatorsPresent = 2 },
		func(w *coreStepRLP) { w.Environment[0].KeyPresent[0] = 2 },
	} {
		w := wire
		w.Environment = append([]coreEnvRLP(nil), wire.Environment...)
		w.Environment[0].KeyPresent = append([]uint64(nil), wire.Environment[0].KeyPresent...)
		change(&w)
		body, err := rlp.Encode(&w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBody(KindCoreStep, body); err == nil {
			t.Fatal("invalid core source accepted")
		}
	}
}

func TestCoreStepRecordQueueBudgetAndKindGap(t *testing.T) {
	fs := fsys.NewMem()
	w, err := Open(Options{FS: fs, Dir: "/core-gap", QueueRecords: 8, QueueBytes: 64}, ident())
	if err != nil {
		t.Fatal(err)
	}
	s := minimalCoreSource(t)
	s.Observed.Mono = int64(23 * time.Second)
	if monoOf(Record{Body: s}) != 23*time.Second || size(Record{Body: s}) < 1024+int64(len(s.Input)+len(s.Outputs)) {
		t.Fatal("core source not included in byte/clock accounting")
	}
	w.Put(Record{Body: s})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(fs, "/core-gap")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if gap, ok := record.Body.(*GapRec); ok {
			for _, k := range gap.ByKind {
				if k.Kind == uint64(KindCoreStep) && k.Count == 1 && gap.FirstMono == 23*time.Second && gap.LastMono == 23*time.Second {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("missing core source was not reported explicitly")
	}
}
