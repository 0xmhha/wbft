package stepdriver

import (
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// fixture builds steps cases for four validators with the keys of the
// specification's vectors; node 1 runs the core and the head is block 9 of
// validator 3, so validator 0 proposes round 0 of height 10.
type fixture struct {
	t     *testing.T
	keys  []*ecdsa.PrivateKey
	blsK  []*bls.SecretKey
	addrs []types.Address
}

func vectorKey(i int) []byte {
	return keccak.Sum256Bytes([]byte("wbft-spec-vector-key-" + strconv.Itoa(i)))
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t}
	for i := 0; i < 5; i++ {
		k, err := ecdsa.PrivateKeyFromBytes(vectorKey(i))
		if err != nil {
			t.Fatal(err)
		}
		b, err := bls.DeriveSecretKey(vectorKey(i))
		if err != nil {
			t.Fatal(err)
		}
		f.keys, f.blsK, f.addrs = append(f.keys, k), append(f.blsK, b), append(f.addrs, ecdsa.Address(k))
	}
	return f
}

func (f *fixture) block(number uint64, tag byte, coinbase types.Address) *types.Block {
	vanity := make([]byte, types.ExtraVanity)
	vanity[0] = tag
	extra, err := codec.EncodeExtra(&types.WBFTExtra{VanityData: vanity, RandaoReveal: []byte{}})
	if err != nil {
		f.t.Fatal(err)
	}
	return &types.Block{Header: &types.Header{
		ParentHash: types.Hash{byte(number), tag},
		UncleHash:  types.EmptyUncleHash,
		Coinbase:   coinbase,
		Difficulty: big.NewInt(1),
		Number:     types.HeightFromUint64(number),
		GasLimit:   30_000_000,
		Time:       1_700_000_000 + number,
		Extra:      extra,
	}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

func (f *fixture) enc(b *types.Block) string {
	e, err := codec.EncodeBlock(b)
	if err != nil {
		f.t.Fatal(err)
	}
	return hexOut(e)
}

func (f *fixture) sign(i int, m *codec.Message, sealType *types.SealType, b *types.Block) string {
	c := *m
	if sealType != nil {
		c.Seal = f.blsK[i].Sign(codec.SealData(b.Header, uint32(c.View.Round.RefLow64()), *sealType)).Bytes()
	}
	p, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if c.Signature, err = ecdsa.SignData(p, f.keys[i]); err != nil {
		f.t.Fatal(err)
	}
	e, err := codec.EncodeMessage(&c)
	if err != nil {
		f.t.Fatal(err)
	}
	return hexOut(e)
}

func v(seq, round uint64) types.View {
	return types.View{Sequence: types.HeightFromUint64(seq), Round: types.RoundFromUint64(round)}
}

func (f *fixture) preprepare(i int, b *types.Block) string {
	return f.sign(i, &codec.Message{Code: codec.CodePreprepare, View: v(10, 0), Proposal: b}, nil, b)
}

func (f *fixture) prepare(i int, b *types.Block) string {
	t := types.PrepareSeal
	return f.sign(i, &codec.Message{Code: codec.CodePrepare, View: v(10, 0), Digest: codec.BlockHash(b.Header)}, &t, b)
}

// input returns a case input with the given steps; network cases add the
// engine state and the peers 0, 2 and 3.
func (f *fixture) input(network bool, engine string, sync bool, steps ...obj) json.RawMessage {
	vals := make([]any, 4)
	for i := range vals {
		vals[i] = obj{"address": addrOut(f.addrs[i]), "bls_public_key": hexOut(f.blsK[i].PublicKey().Bytes())}
	}
	ini := obj{
		"validators":      vals,
		"proposer_policy": "0",
		"node_key":        hexOut(vectorKey(1)),
		"head":            f.enc(f.block(9, 0, f.addrs[3])),
		"app":             obj{"invalid_proposals": []any{}, "future_proposals": []any{}, "bad_blocks": []any{}, "finalize": "ok"},
	}
	if network {
		ini["engine"] = engine
		ini["synchronising"] = sync
		ini["peers"] = []any{addrOut(f.addrs[0]), addrOut(f.addrs[2]), addrOut(f.addrs[3])}
	}
	st := make([]any, len(steps))
	for i, s := range steps {
		s["label"] = "step"
		st[i] = s
	}
	b, err := json.Marshal(obj{"initial": ini, "steps": st})
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func run(t *testing.T, handler string, in json.RawMessage, opts Options) []obj {
	t.Helper()
	out, err := Run(handler, in, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	var doc struct {
		Start obj   `json:"start"`
		Steps []obj `json:"steps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return append([]obj{doc.Start}, doc.Steps...)
}

func TestRunRounds(t *testing.T) {
	f := newFixture(t)
	b := f.block(10, 1, f.addrs[0])
	recs := run(t, HandlerRounds, f.input(false, "", false,
		obj{"kind": "message", "code": "19", "payload": f.prepare(2, b)},
		obj{"kind": "message", "code": "18", "payload": f.preprepare(0, b)},
		obj{"kind": "backlog", "code": "19", "payload": f.prepare(2, b)},
		obj{"kind": "round_timeout"},
		obj{"kind": "stop"},
		obj{"kind": "round_timeout", "timer": "0"},
		obj{"kind": "start"},
	), Options{})
	start := recs[0]
	if start["new_round"].([]any)[0] != "0" || len(start["timers"].([]any)) != 1 {
		t.Fatalf("start %v", start)
	}
	// FUTURE PREPARE: backlogged, not relayed.
	if recs[1]["check"] != "FUTURE" || recs[1]["relay"] != false {
		t.Fatalf("step 0 %v", recs[1])
	}
	// PRE-PREPARE: accepted, PREPARE sent, the PREPARE of validator 2
	// scheduled for replay.
	s1 := recs[2]
	if s1["check"] != "PROCESS" || s1["relay"] != true || len(s1["sent"].([]any)) != 1 || len(s1["scheduled"].([]any)) != 1 {
		t.Fatalf("step 1 %v", s1)
	}
	if sent := s1["sent"].([]any)[0].(map[string]any); sent["type"] != "PREPARE" || sent["encoded"] == nil {
		t.Fatalf("sent %v", sent)
	}
	// The replay is processed and relayed.
	if recs[3]["check"] != "PROCESS" || recs[3]["relay"] != true {
		t.Fatalf("step 2 %v", recs[3])
	}
	if prepares := recs[3]["state"].(map[string]any)["prepares"].([]any); len(prepares) != 1 {
		t.Fatalf("prepares %v", prepares)
	}
	// Round timeout: ROUND-CHANGE and two timers.
	if timers := recs[4]["timers"].([]any); len(timers) != 2 {
		t.Fatalf("timers %v", timers)
	}
	// Stopped: no state; a timer step has no effect; start enters (10, 0).
	if recs[5]["state"] != nil || recs[6]["state"] != nil || recs[6]["new_round"].([]any) == nil {
		t.Fatalf("stopped %v %v", recs[5], recs[6])
	}
	if view := recs[7]["state"].(map[string]any)["view"].(map[string]any); view["sequence"] != "10" || view["round"] != "0" {
		t.Fatalf("restart view %v", view)
	}
}

func TestRunNetworkFrames(t *testing.T) {
	f := newFixture(t)
	b := f.block(10, 1, f.addrs[0])
	pp := f.preprepare(0, b)
	frame := func(peer int, code string, payload string) obj {
		return obj{"kind": "frame", "peer": addrOut(f.addrs[peer]), "code": code, "payload": payload}
	}
	in := f.input(true, "running", false,
		frame(0, "18", pp),
		frame(2, "18", pp),
		frame(3, "19", f.prepare(4, b)),
	)
	recs := run(t, HandlerReceiveOutcome, in, Options{})
	if recs[1]["outcome"] != "ACCEPT" || recs[1]["dedup_key"] == nil {
		t.Fatalf("accept %v", recs[1])
	}
	relayTo := recs[1]["relay_to"].([]any)
	if len(relayTo) != 2 {
		t.Fatalf("relay_to %v", relayTo)
	}
	if to := recs[1]["sent"].([]any)[0].(map[string]any)["to"].([]any); len(to) != 3 {
		t.Fatalf("to %v", to)
	}
	if recs[2]["outcome"] != "DROP_SILENT" || recs[2]["relay_to"] != nil {
		t.Fatalf("duplicate %v", recs[2])
	}
	if recs[3]["outcome"] != "IGNORE" || recs[3]["check"] != nil || recs[3]["relay"] != false {
		t.Fatalf("non-validator signer %v", recs[3])
	}

	// Frames whose verdict belongs to the transport adapter.
	for _, fr := range []obj{frame(0, "17", "0x80"), frame(0, "16", "0x80"), frame(0, "18", "0x")} {
		_, err := Run(HandlerReceiveOutcome, f.input(true, "running", false, fr), Options{})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%v: %v", fr, err)
		}
	}
	withFrame := Options{Frame: transportFrame}
	recs = run(t, HandlerReceiveOutcome, f.input(true, "running", false, frame(0, "16", "0x80"), frame(0, "18", "0x"), frame(0, "17", "0xc0")), withFrame)
	if recs[1]["outcome"] != "DROP_SILENT" || recs[2]["outcome"] != "DISCONNECT" || recs[3]["outcome"] != "DISCONNECT" {
		t.Fatalf("frame verdicts %v %v %v", recs[1], recs[2], recs[3])
	}

	// Engine stopped: consensus codes disconnect unless synchronising.
	for sync, want := range map[bool]string{false: "DISCONNECT", true: "DROP_SILENT"} {
		recs := run(t, HandlerReceiveOutcome, f.input(true, "stopped", sync, frame(0, "18", pp)), Options{})
		if recs[0] != nil || recs[1]["outcome"] != want || len(recs[1]) != 3 {
			t.Fatalf("stopped, synchronising %t: %v", sync, recs)
		}
	}
}

func TestRunRejectsMalformedInput(t *testing.T) {
	f := newFixture(t)
	good := f.input(false, "", false)
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	m["extra"] = 1
	bad, _ := json.Marshal(m)
	if _, err := Run(HandlerRounds, bad, Options{}); !errors.Is(err, ErrInput) {
		t.Fatalf("unknown field: %v", err)
	}
	if _, err := Run("state_machine/other", good, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown handler: %v", err)
	}
	if _, err := Run(HandlerRounds, f.input(false, "", false, obj{"kind": "dance"}), Options{}); !errors.Is(err, ErrInput) {
		t.Fatalf("unknown step: %v", err)
	}
}
