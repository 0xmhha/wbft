package inputlog

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("inputlog")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func block(n uint64) *types.Block {
	extra, _ := codec.EncodeExtra(&types.WBFTExtra{VanityData: make([]byte, types.ExtraVanity), RandaoReveal: []byte{}})
	return &types.Block{Header: &types.Header{UncleHash: types.EmptyUncleHash, Difficulty: big.NewInt(1),
		Number: types.HeightFromUint64(n), GasLimit: 7, Time: 99, Extra: extra}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
}

func signed(t *testing.T, m *codec.Message) *codec.Message {
	p, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Signature, err = ecdsa.SignData(p, key(t)); err != nil {
		t.Fatal(err)
	}
	return m
}

func view(s, r uint64) types.View {
	return types.View{Sequence: types.HeightFromUint64(s), Round: types.RoundFromUint64(r)}
}

func inputs(t *testing.T) []consensus.Input {
	prep := signed(t, &codec.Message{Code: codec.CodePrepare, View: view(5, 1), Digest: types.Hash{1}, Seal: make([]byte, 96)})
	rc := signed(t, &codec.Message{Code: codec.CodeRoundChange, View: view(5, 2)})
	pp := signed(t, &codec.Message{Code: codec.CodePreprepare, View: view(5, 2), Proposal: block(5), RoundChanges: []*codec.Message{rc}, Prepares: []*codec.Message{prep}})
	payload, _ := codec.EncodeMessage(pp)
	v, err := consensus.Recover(codec.CodePreprepare, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return []consensus.Input{
		consensus.Start{},
		consensus.Stop{},
		consensus.NewHead{Header: block(4).Header},
		consensus.NewHead{},
		consensus.Request{Block: block(5)},
		consensus.Message{Code: codec.CodePreprepare, Payload: payload, Peer: types.Address{7}, RecvMono: 12345 * time.Millisecond},
		consensus.Replay{Msg: v},
		consensus.Timeout{Kind: consensus.RoundTimer, View: view(5, 3), Round: types.RoundFromUint64(3), Gen: 9},
		consensus.Timeout{Kind: consensus.FutureTimer, View: view(5, 2), Round: types.RoundFromUint64(2), Gen: 2, Msg: v},
		consensus.CommitResult{Hash: types.Hash{3}},
		consensus.CommitResult{Hash: types.Hash{3}, Err: errors.New("import failed")},
		consensus.BroadcastFailed{Code: codec.CodeCommit, View: view(8, 1)},
		consensus.PeerConnected{Addr: types.Address{9}},
	}
}

func TestRoundTrip(t *testing.T) {
	for _, in := range inputs(t) {
		b, err := Encode(in)
		if err != nil {
			t.Fatalf("%T: %v", in, err)
		}
		out, err := Decode(Kind(in), b, nil)
		if err != nil {
			t.Fatalf("%T: %v", in, err)
		}
		b2, err := Encode(out)
		if err != nil || !bytes.Equal(b, b2) {
			t.Fatalf("%T: encoding changed after a round trip", in)
		}
		if fmt.Sprintf("%T", in) != fmt.Sprintf("%T", out) {
			t.Fatalf("%T decoded as %T", in, out)
		}
	}
	// A replay keeps its signers without recovering them again.
	in := inputs(t)[6].(consensus.Replay)
	b, _ := Encode(in)
	out, _ := Decode(KindBacklog, b, nil)
	r := out.(consensus.Replay)
	if r.Msg.Source != in.Msg.Source || len(r.Msg.RoundChangeSources) != 1 || len(r.Msg.PrepareSources) != 1 {
		t.Fatal("replay signers")
	}
}

func TestMessageReference(t *testing.T) {
	b, _ := rlp.Encode(&messageRLP{Code: 0x13, Peer: types.Address{1}, Ref: 42})
	if _, err := Decode(KindMessage, b, nil); !errors.Is(err, ErrDecode) {
		t.Fatalf("reference without resolver: %v", err)
	}
	in, err := Decode(KindMessage, b, func(j uint64) ([]byte, error) {
		if j != 42 {
			return nil, errors.New("unknown")
		}
		return []byte{0xc0}, nil
	})
	if err != nil || !bytes.Equal(in.(consensus.Message).Payload, []byte{0xc0}) {
		t.Fatalf("resolved message: %v", err)
	}
	for _, k := range []string{KindStart, KindNewHead, KindTimeout, "nope"} {
		if _, err := Decode(k, []byte{0x01}, nil); !errors.Is(err, ErrDecode) {
			t.Fatalf("%s: %v", k, err)
		}
	}
}

func TestEnvRoundTrip(t *testing.T) {
	bk, _ := bls.DeriveSecretKey(keccak.Sum256Bytes([]byte("bls")))
	vs, _ := validator.NewSet([]types.Address{{1}, {2}}, [][]byte{bk.PublicKey().Bytes(), bk.PublicKey().Bytes()}, types.ProposerPolicy{ID: 1})
	calls := []EnvCall{
		{Kind: EnvValidatorsAt, Number: types.HeightFromUint64(10), Key: types.Hash{1}, Validators: vs},
		{Kind: EnvValidatorsAt, Number: types.HeightFromUint64(10), Key: types.Hash{1}, Err: "unknown ancestor"},
		ProposalCall(types.Hash{2}, 0, nil),
		ProposalCall(types.Hash{2}, 3*time.Second, fmt.Errorf("x: %w", header.ErrFutureBlock)),
		ProposalCall(types.Hash{2}, 0, &header.StepError{Step: "H18", Class: "ErrInvalidRandaoReveal", Err: header.ErrInvalidRandaoReveal}),
		{Kind: EnvIsBadBlock, Key: types.Hash{4}, Bad: true},
	}
	for i, c := range calls {
		b, err := EncodeEnv(c)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DecodeEnv(b)
		if err != nil {
			t.Fatal(err)
		}
		b2, _ := EncodeEnv(d)
		if !bytes.Equal(b, b2) {
			t.Fatalf("call %d changed", i)
		}
	}
	if consensus.ValsetDigest(vs) == (types.Hash{}) {
		t.Fatal("valset digest")
	}
	d, _ := DecodeEnv(mustEnv(t, calls[3]))
	if f, err := d.ProposalAnswer(); f != 3*time.Second || !errors.Is(err, header.ErrFutureBlock) {
		t.Fatalf("future answer %v %v", f, err)
	}
	d, _ = DecodeEnv(mustEnv(t, calls[4]))
	var se *header.StepError
	if _, err := d.ProposalAnswer(); !errors.As(err, &se) || se.Step != "H18" {
		t.Fatalf("failed answer %v", err)
	}
}

func mustEnv(t *testing.T, c EnvCall) []byte {
	b, err := EncodeEnv(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOutDigest(t *testing.T) {
	ins := inputs(t)
	outs := []consensus.Output{
		consensus.Broadcast{Msg: &codec.Message{Code: codec.CodePrepare, View: view(1, 0)}, SealData: []byte{1}},
		consensus.Relay{Code: codec.CodeCommit, Payload: []byte{1, 2}},
		consensus.Schedule{In: ins[6]},
		consensus.ArmTimer{Kind: consensus.FutureTimer, View: view(1, 0), Duration: time.Second, Gen: 3, Msg: ins[6].(consensus.Replay).Msg},
		consensus.CancelTimers{Kinds: consensus.AllTimers},
		consensus.RequestBuild{Height: types.HeightFromUint64(2), Round: types.RoundFromUint64(0), HeadTime: 5, BlockPeriod: 1},
		consensus.Commit{Block: block(3), Round: types.RoundFromUint64(1)},
		consensus.Outcome{Code: codec.CodePrepare, Check: consensus.Process, Row: 17, Relayed: true, Via: "direct"},
		consensus.Event{Record: event.Record{Kind: event.Quorum, View: event.ViewOf(view(1, 0)), Fields: map[string]any{"b": 1, "a": "x"}}},
	}
	d1, err := OutDigest(outs)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := OutDigest(outs)
	if d1 != d2 {
		t.Fatal("digest is not repeatable")
	}
	d3, _ := OutDigest(outs[1:])
	if d3 == d1 {
		t.Fatal("digest ignores an output")
	}
}
