package inputlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// Format is the version of the encodings of this package; a change of any
// encoding raises it.
const Format = 1

// Input kinds, as the journal spells them.
const (
	KindStart           = "start"
	KindStop            = "stop"
	KindNewHead         = "new_head"
	KindRequest         = "request"
	KindMessage         = "message"
	KindBacklog         = "backlog"
	KindTimeout         = "timeout"
	KindCommitResult    = "commit_result"
	KindBroadcastFailed = "broadcast_failed"
	KindPeerConnected   = "peer_connected"
)

// ErrDecode reports a body that does not decode as its kind.
var ErrDecode = errors.New("inputlog: malformed input record")

// Kind returns the kind of in.
func Kind(in consensus.Input) string {
	switch in.(type) {
	case consensus.Start:
		return KindStart
	case consensus.Stop:
		return KindStop
	case consensus.NewHead:
		return KindNewHead
	case consensus.Request:
		return KindRequest
	case consensus.Message:
		return KindMessage
	case consensus.Replay:
		return KindBacklog
	case consensus.Timeout:
		return KindTimeout
	case consensus.CommitResult:
		return KindCommitResult
	case consensus.BroadcastFailed:
		return KindBroadcastFailed
	case consensus.PeerConnected:
		return KindPeerConnected
	}
	return ""
}

// verifiedRLP is a message with the signers recovered from it.
type verifiedRLP struct {
	Code          uint64
	Payload       []byte
	Source        types.Address
	RoundChangeBy []types.Address
	PrepareBy     []types.Address
}

func encodeVerified(v *consensus.Verified) (verifiedRLP, error) {
	p, err := v.Encode()
	if err != nil {
		return verifiedRLP{}, err
	}
	return verifiedRLP{Code: uint64(v.Msg.Code), Payload: p, Source: v.Source,
		RoundChangeBy: nonNil(v.RoundChangeSources), PrepareBy: nonNil(v.PrepareSources)}, nil
}

func nonNil(as []types.Address) []types.Address {
	if as == nil {
		return []types.Address{}
	}
	return as
}

func (w verifiedRLP) decode() (*consensus.Verified, error) {
	m, err := codec.DecodeMessage(codec.Code(w.Code), w.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	v := &consensus.Verified{Msg: m, Source: w.Source}
	if len(w.RoundChangeBy) > 0 {
		v.RoundChangeSources = w.RoundChangeBy
	}
	if len(w.PrepareBy) > 0 {
		v.PrepareSources = w.PrepareBy
	}
	if len(v.RoundChangeSources) != len(m.RoundChanges) || len(v.PrepareSources) != len(m.Prepares) {
		return nil, fmt.Errorf("%w: justification signers", ErrDecode)
	}
	return v, nil
}

type messageRLP struct {
	Code     uint64
	Payload  []byte
	Peer     types.Address
	RecvMono uint64
	Ref      uint64 // journal jseq of the bytes; 0: Payload holds them
}

type timeoutRLP struct {
	Kind   uint64
	Seq    *big.Int
	VRound *big.Int
	Round  *big.Int
	Gen    uint64
	HasMsg uint64
	Msg    verifiedRLP
}

type viewRLP struct {
	Code  uint64
	Seq   *big.Int
	Round *big.Int
}

type commitResultRLP struct {
	Hash types.Hash
	Err  string
}

// Encode writes one core input as stored in WAL "input" and journal "step"
// records: an RLP list whose shape depends on the kind (Kind).
func Encode(in consensus.Input) ([]byte, error) {
	switch v := in.(type) {
	case consensus.Start, consensus.Stop:
		return rlp.Encode([]any{})
	case consensus.NewHead:
		if v.Header == nil {
			return rlp.Encode([]any{[]byte{}})
		}
		h, err := codec.EncodeHeader(v.Header)
		if err != nil {
			return nil, err
		}
		return rlp.Encode([]any{h})
	case consensus.Request:
		b, err := codec.EncodeBlock(v.Block)
		if err != nil {
			return nil, err
		}
		return rlp.Encode([]any{b})
	case consensus.Message:
		return rlp.Encode(&messageRLP{Code: uint64(v.Code), Payload: v.Payload, Peer: v.Peer, RecvMono: uint64(int64(v.RecvMono))})
	case consensus.Replay:
		w, err := encodeVerified(v.Msg)
		if err != nil {
			return nil, err
		}
		return rlp.Encode(&w)
	case consensus.Timeout:
		t := timeoutRLP{Kind: uint64(v.Kind), Seq: v.View.Sequence.Big(), VRound: v.View.Round.Big(), Round: v.Round.Big(), Gen: v.Gen,
			Msg: verifiedRLP{RoundChangeBy: []types.Address{}, PrepareBy: []types.Address{}}}
		if v.Msg != nil {
			w, err := encodeVerified(v.Msg)
			if err != nil {
				return nil, err
			}
			t.HasMsg, t.Msg = 1, w
		}
		return rlp.Encode(&t)
	case consensus.CommitResult:
		c := commitResultRLP{Hash: v.Hash}
		if v.Err != nil {
			c.Err = v.Err.Error()
		}
		return rlp.Encode(&c)
	case consensus.BroadcastFailed:
		return rlp.Encode(&viewRLP{Code: uint64(v.Code), Seq: v.View.Sequence.Big(), Round: v.View.Round.Big()})
	case consensus.PeerConnected:
		return rlp.Encode([]any{v.Addr})
	}
	return nil, fmt.Errorf("inputlog: unknown input %T", in)
}

func height(b *big.Int) (types.Height, error) {
	if b == nil {
		return types.HeightFromUint64(0), nil
	}
	return types.HeightFromBig(b)
}

func round(b *big.Int) (types.Round, error) {
	if b == nil {
		return types.RoundFromUint64(0), nil
	}
	return types.RoundFromBig(b)
}

func viewOf(seq, r *big.Int) (types.View, error) {
	s, err := height(seq)
	if err != nil {
		return types.View{}, err
	}
	rr, err := round(r)
	if err != nil {
		return types.View{}, err
	}
	return types.View{Sequence: s, Round: rr}, nil
}

// errCommit is the error of a decoded failed CommitResult.
type errCommit struct{ msg string }

func (e *errCommit) Error() string { return e.msg }

// Decode is the inverse of Encode. msgs resolves a journal jseq to the raw
// bytes of a message input that refers to a journal "msg" record; it may be
// nil when no record refers to one.
func Decode(kind string, body []byte, msgs func(jseq uint64) ([]byte, error)) (consensus.Input, error) {
	fail := func(err error) (consensus.Input, error) { return nil, fmt.Errorf("%w: %s: %v", ErrDecode, kind, err) }
	switch kind {
	case KindStart, KindStop:
		var x []rlp.RawValue
		if err := rlp.DecodeStrict(body, &x); err != nil || len(x) != 0 {
			return fail(fmt.Errorf("want an empty list"))
		}
		if kind == KindStart {
			return consensus.Start{}, nil
		}
		return consensus.Stop{}, nil
	case KindNewHead:
		var x [][]byte
		if err := rlp.DecodeStrict(body, &x); err != nil || len(x) != 1 {
			return fail(fmt.Errorf("want [header]"))
		}
		if len(x[0]) == 0 {
			return consensus.NewHead{}, nil
		}
		h, err := codec.DecodeHeader(x[0])
		if err != nil {
			return fail(err)
		}
		return consensus.NewHead{Header: h}, nil
	case KindRequest:
		var x [][]byte
		if err := rlp.DecodeStrict(body, &x); err != nil || len(x) != 1 {
			return fail(fmt.Errorf("want [block]"))
		}
		b, err := codec.DecodeBlock(x[0])
		if err != nil {
			return fail(err)
		}
		return consensus.Request{Block: b}, nil
	case KindMessage:
		var m messageRLP
		if err := rlp.DecodeStrict(body, &m); err != nil {
			return fail(err)
		}
		payload := m.Payload
		if m.Ref != 0 {
			if msgs == nil {
				return fail(fmt.Errorf("message record %d without a resolver", m.Ref))
			}
			b, err := msgs(m.Ref)
			if err != nil {
				return fail(err)
			}
			payload = b
		}
		return consensus.Message{Code: codec.Code(m.Code), Payload: payload, Peer: m.Peer, RecvMono: time.Duration(int64(m.RecvMono))}, nil
	case KindBacklog:
		var w verifiedRLP
		if err := rlp.DecodeStrict(body, &w); err != nil {
			return fail(err)
		}
		v, err := w.decode()
		if err != nil {
			return fail(err)
		}
		return consensus.Replay{Msg: v}, nil
	case KindTimeout:
		var t timeoutRLP
		if err := rlp.DecodeStrict(body, &t); err != nil {
			return fail(err)
		}
		v, err := viewOf(t.Seq, t.VRound)
		if err != nil {
			return fail(err)
		}
		r, err := round(t.Round)
		if err != nil {
			return fail(err)
		}
		out := consensus.Timeout{Kind: consensus.TimerKind(t.Kind), View: v, Round: r, Gen: t.Gen}
		if t.HasMsg == 1 {
			m, err := t.Msg.decode()
			if err != nil {
				return fail(err)
			}
			out.Msg = m
		}
		return out, nil
	case KindCommitResult:
		var c commitResultRLP
		if err := rlp.DecodeStrict(body, &c); err != nil {
			return fail(err)
		}
		out := consensus.CommitResult{Hash: c.Hash}
		if c.Err != "" {
			out.Err = &errCommit{c.Err}
		}
		return out, nil
	case KindBroadcastFailed:
		var x viewRLP
		if err := rlp.DecodeStrict(body, &x); err != nil {
			return fail(err)
		}
		v, err := viewOf(x.Seq, x.Round)
		if err != nil {
			return fail(err)
		}
		return consensus.BroadcastFailed{Code: codec.Code(x.Code), View: v}, nil
	case KindPeerConnected:
		var x []types.Address
		if err := rlp.DecodeStrict(body, &x); err != nil || len(x) != 1 {
			return fail(fmt.Errorf("want [address]"))
		}
		return consensus.PeerConnected{Addr: x[0]}, nil
	}
	return nil, fmt.Errorf("%w: unknown kind %q", ErrDecode, kind)
}

// ---------------------------------------------------------------- Env

// Env call kinds.
const (
	EnvValidatorsAt     uint8 = 1
	EnvValidateProposal uint8 = 2
	EnvIsBadBlock       uint8 = 3
)

// Results of ValidateProposal.
const (
	ProposalValid  uint8 = 0
	ProposalFuture uint8 = 1
	ProposalFailed uint8 = 2
)

// EnvCall is one Env call of the core and its answer. The arguments are
// Number and Key (the parent hash for ValidatorsAt, the block hash
// otherwise); the answer fields depend on the kind.
type EnvCall struct {
	Kind   uint8
	Number types.Height
	Key    types.Hash

	// ValidatorsAt
	Validators *validator.Set // nil: the lookup failed with Err
	// ValidateProposal
	Result uint8
	Future time.Duration
	Step   string // failing step of a failed proposal, "" if unknown
	Class  string // error class of a failed proposal
	// IsBadBlock
	Bad bool

	Err string
}

type envRLP struct {
	Kind     uint64
	Number   *big.Int
	Key      types.Hash
	HasSet   uint64
	Policy   uint64
	Addrs    []types.Address
	Keys     [][]byte
	Result   uint64
	Future   uint64
	Step     string
	Class    string
	Bad      uint64
	ErrorMsg string
}

// EncodeEnv encodes an Env call and its answer.
func EncodeEnv(c EnvCall) ([]byte, error) {
	w := envRLP{Kind: uint64(c.Kind), Number: c.Number.Big(), Key: c.Key, Result: uint64(c.Result),
		Future: uint64(int64(c.Future)), Step: c.Step, Class: c.Class, ErrorMsg: c.Err, Addrs: []types.Address{}, Keys: [][]byte{}}
	if c.Validators != nil {
		w.HasSet, w.Policy = 1, c.Validators.Policy().ID
		for i := 0; i < c.Validators.Len(); i++ {
			m := c.Validators.At(i)
			w.Addrs = append(w.Addrs, m.Addr)
			w.Keys = append(w.Keys, m.BLSPublicKey)
		}
	}
	if c.Bad {
		w.Bad = 1
	}
	return rlp.Encode(&w)
}

// DecodeEnv is the inverse of EncodeEnv.
func DecodeEnv(b []byte) (EnvCall, error) {
	var w envRLP
	if err := rlp.DecodeStrict(b, &w); err != nil {
		return EnvCall{}, fmt.Errorf("%w: env: %v", ErrDecode, err)
	}
	n, err := height(w.Number)
	if err != nil {
		return EnvCall{}, fmt.Errorf("%w: env: %v", ErrDecode, err)
	}
	c := EnvCall{Kind: uint8(w.Kind), Number: n, Key: w.Key, Result: uint8(w.Result), Future: time.Duration(int64(w.Future)),
		Step: w.Step, Class: w.Class, Bad: w.Bad == 1, Err: w.ErrorMsg}
	if w.HasSet == 1 {
		vs, err := validator.NewSet(w.Addrs, w.Keys, types.ProposerPolicy{ID: w.Policy})
		if err != nil {
			return EnvCall{}, fmt.Errorf("%w: env: %v", ErrDecode, err)
		}
		c.Validators = vs
	}
	return c, nil
}

// ProposalCall records the answer of ValidateProposal for block hash h.
func ProposalCall(h types.Hash, future time.Duration, err error) EnvCall {
	c := EnvCall{Kind: EnvValidateProposal, Key: h}
	switch {
	case err == nil:
		c.Result = ProposalValid
	case errors.Is(err, header.ErrFutureBlock):
		c.Result, c.Future = ProposalFuture, future
	default:
		c.Result = ProposalFailed
		c.Err = err.Error()
		var se *header.StepError
		if errors.As(err, &se) {
			c.Step, c.Class = se.Step, se.Class
		}
	}
	return c
}

// errReplayedProposal is the error of a recorded failed proposal.
type errReplayedProposal struct{ msg string }

func (e *errReplayedProposal) Error() string { return e.msg }

// ProposalAnswer returns the answer ValidateProposal gave, as recorded.
func (c EnvCall) ProposalAnswer() (time.Duration, error) {
	switch c.Result {
	case ProposalValid:
		return 0, nil
	case ProposalFuture:
		return c.Future, &header.StepError{Step: "H2", Class: "ErrFutureBlock", Err: header.ErrFutureBlock}
	}
	return 0, &header.StepError{Step: c.Step, Class: c.Class, Err: &errReplayedProposal{c.Err}}
}

// ---------------------------------------------------------------- outputs

// EncodeOutputs encodes the outputs of one Step in order, the input of
// OutDigest. Validator sets are given by ValsetDigest and messages by their
// encoding without signature.
func EncodeOutputs(outs []consensus.Output) ([]byte, error) {
	items := make([]any, 0, len(outs))
	for _, o := range outs {
		it, err := encodeOutput(o)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return rlp.Encode(items)
}

// OutDigest is keccak256(EncodeOutputs(outs)): the out_digest of a journal
// "step" record.
func OutDigest(outs []consensus.Output) (types.Hash, error) {
	b, err := EncodeOutputs(outs)
	if err != nil {
		return types.Hash{}, err
	}
	return keccak.Sum256(b), nil
}

func msgBytes(m *codec.Message) []byte {
	if m == nil {
		return []byte{}
	}
	b, err := codec.EncodeMessage(m)
	if err != nil {
		return []byte(err.Error())
	}
	return b
}

func encodeOutput(o consensus.Output) (any, error) {
	switch v := o.(type) {
	case consensus.Broadcast:
		it := []any{uint64(1), msgBytes(v.Msg), bytesOrEmpty(v.SealData), consensus.ValsetDigest(v.Validators)}
		if v.BadBlockReleased {
			// Appended only when set, so the digests of earlier journals
			// do not change.
			it = append(it, uint64(1))
		}
		return it, nil
	case consensus.Relay:
		return []any{uint64(2), uint64(v.Code), v.Payload, consensus.ValsetDigest(v.Validators)}, nil
	case consensus.Schedule:
		b, err := Encode(v.In)
		if err != nil {
			return nil, err
		}
		return []any{uint64(3), Kind(v.In), rlp.RawValue(b)}, nil
	case consensus.ArmTimer:
		msg := []byte{}
		if v.Msg != nil {
			w, err := encodeVerified(v.Msg)
			if err != nil {
				return nil, err
			}
			msg = w.Payload
		}
		return []any{uint64(4), uint64(v.Kind), v.View.Sequence.Big(), v.View.Round.Big(), v.Round.Big(), uint64(int64(v.Duration)), v.Gen, v.Digest, msg}, nil
	case consensus.CancelTimers:
		ks := make([]uint64, len(v.Kinds))
		for i, k := range v.Kinds {
			ks[i] = uint64(k)
		}
		return []any{uint64(5), ks}, nil
	case consensus.RequestBuild:
		return []any{uint64(6), v.Height.Big(), v.Round.Big(), v.HeadTime, v.BlockPeriod}, nil
	case consensus.Commit:
		b, err := codec.EncodeBlock(v.Block)
		if err != nil {
			return nil, err
		}
		return []any{uint64(7), b, v.Round.Big()}, nil
	case consensus.Outcome:
		relayed := uint64(0)
		if v.Relayed {
			relayed = 1
		}
		return []any{uint64(8), uint64(v.Code), v.Source, v.View.Sequence.Big(), v.View.Round.Big(), uint64(v.Check), uint64(v.Row), relayed, v.Via, v.Peer, v.DedupKey}, nil
	case consensus.Event:
		b, err := json.Marshal(struct {
			Kind   string         `json:"kind"`
			View   any            `json:"view"`
			Imp    []string       `json:"imp"`
			Src    string         `json:"src"`
			Fields map[string]any `json:"fields"`
		}{string(v.Record.Kind), v.Record.View, v.Record.Imp, v.Record.Src, v.Record.Fields})
		if err != nil {
			return nil, err
		}
		return []any{uint64(9), b}, nil
	}
	return nil, fmt.Errorf("inputlog: unknown output %T", o)
}

func bytesOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
