package stepdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/header"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/privval"
	"github.com/0xmhha/wbft/transport"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// ErrUnsupported is returned for a case that needs a stage the driver was not
// given: a frame whose verdict belongs to the transport adapter.
var ErrUnsupported = errors.New("stepdriver: unsupported case")

// FrameAction is the frame verdict of transport.DecodeFrame.
type FrameAction = transport.FrameAction

// FrameDecoder is the frame stage of a frame step, supplied by a transport
// adapter: size limit, 0x11 unwrap, empty payload, code range and NewBlock.
// The driver records FrameDrop as DROP_SILENT and FrameDisconnect as
// DISCONNECT and feeds delivered data to the deduplication caches and the
// core.
type FrameDecoder func(code uint64, payload []byte) (data []byte, deliverCode uint64, act FrameAction, reason string)

// Options configure Run.
type Options struct {
	// Frame is the frame stage of frame steps. Nil: frames whose verdict
	// depends on it (codes other than 0x12 .. 0x15, 0x11 while the engine
	// runs, empty or oversized payloads) make the case unsupported.
	Frame FrameDecoder
	// Improvements are the optional behaviours of the core. Conformance
	// runs leave the set empty (the reference behaviour); a node runs
	// consensus.RestartSafety.
	Improvements consensus.ImprovementSet
	// PrivVal signs own messages with a private validator (privval) that
	// starts with an empty sign state on an in-memory file system, as a
	// node does. A refused signature sends nothing, is reported to Refused
	// and is fed back to the core as BroadcastFailed, as the runner does.
	PrivVal bool
	// SignFloor, with PrivVal, sets the sign floor of a node that takes
	// over a key without its sign record: nothing is signed at or below
	// the height of the head plus one.
	SignFloor bool
	// Refused is called for every refused signature; step is the index of
	// the step, -1 for the start.
	Refused func(step int, m *codec.Message, err error)
}

// Handlers answered by Run.
const (
	HandlerRounds         = "state_machine/rounds"
	HandlerReceiveOutcome = "network/receive_outcome"
)

// Run drives a consensus core through one steps case and returns the
// expected-output document: {"start": record, "steps": [record, ...]}.
//
// The core starts as after Start (or stopped, for a network case with a
// stopped engine). Scheduled events are kept in a queue addressed by content
// and processed only when a step names them; timers expire only through
// steps.
func Run(handler string, input json.RawMessage, opts Options) (any, error) {
	var network bool
	switch handler {
	case HandlerRounds:
	case HandlerReceiveOutcome:
		network = true
	default:
		return nil, fmt.Errorf("%w: handler %s", ErrUnsupported, handler)
	}
	in, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	d, err := newDriver(in, network, opts)
	if err != nil {
		return nil, err
	}
	return d.run(in.Steps)
}

type timerRec struct {
	gen    uint64
	live   bool
	digest types.Hash
}

type driver struct {
	network bool
	opts    Options
	state   *consensus.State
	env     *env
	key     *ecdsa.PrivateKey
	blsKey  *bls.SecretKey
	self    types.Address

	running       bool
	synchronising bool
	tr            *fakeTransport
	dedup         *transport.Dedup

	queue  []consensus.Input
	timers map[consensus.TimerKind][]*timerRec
	rec    *record

	signer  privval.Signer    // PrivVal only
	failed  []consensus.Input // BroadcastFailed inputs of refused signatures
	stepIdx int
}

func newDriver(in *caseInput, network bool, opts Options) (*driver, error) {
	ini := in.Initial
	key, err := ecdsa.PrivateKeyFromBytes(ini.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("%w: node key: %v", ErrInput, err)
	}
	blsKey, err := bls.DeriveSecretKey(ini.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("%w: node key: %v", ErrInput, err)
	}
	policyID, err := ini.ProposerPolicy.uint64()
	if err != nil {
		return nil, err
	}
	policy := types.ProposerPolicy{ID: policyID}
	addrs := make([]types.Address, len(ini.Validators))
	keys := make([][]byte, len(ini.Validators))
	for i, v := range ini.Validators {
		if len(v.Address) != 20 {
			return nil, fmt.Errorf("%w: validator address of %d bytes", ErrInput, len(v.Address))
		}
		addrs[i] = types.Address(v.Address)
		keys[i] = v.BLSPublicKey
	}
	vs, err := validator.NewSet(addrs, keys, policy)
	if err != nil {
		return nil, err
	}
	head, err := codec.DecodeBlock(ini.Head)
	if err != nil {
		return nil, fmt.Errorf("%w: head: %v", ErrInput, err)
	}
	e := &env{
		head:     head,
		vs:       vs,
		invalid:  hashSet(ini.App.InvalidProposals),
		future:   hashSet(ini.App.FutureProposals),
		released: map[types.Hash]bool{},
		bad:      hashSet(ini.App.BadBlocks),
	}
	switch ini.App.Finalize {
	case "ok":
	case "fail":
		e.finalizeFail = true
	default:
		return nil, fmt.Errorf("%w: finalize %q", ErrInput, ini.App.Finalize)
	}
	self := ecdsa.Address(key)
	cfg := types.NewConfig(types.WBFTParams{
		RequestTimeoutSeconds: 2,
		BlockPeriodSeconds:    1,
		EpochLength:           1 << 40,
		ProposerPolicy:        &policyID,
	}, nil, types.GenesisInit{}, nil)
	var signer privval.Signer
	if opts.PrivVal {
		mem := fsys.NewMem()
		if err := mem.MkdirAll("/privval", 0o700); err != nil {
			return nil, err
		}
		pv, err := privval.NewKeySigner(mem, nil, ini.NodeKey, "/privval/state")
		if err != nil {
			return nil, err
		}
		if opts.SignFloor {
			if err := pv.InitSignFloor(head.Header.Number.AddUint64(1)); err != nil {
				return nil, err
			}
		}
		signer = pv
	}
	d := &driver{
		network: network,
		opts:    opts,
		state:   consensus.NewState(consensus.Options{Config: cfg, Self: self, Improvements: opts.Improvements}),
		signer:  signer,
		env:     e,
		key:     key,
		blsKey:  blsKey,
		self:    self,
		running: true,
		timers:  map[consensus.TimerKind][]*timerRec{},
	}
	if network {
		if ini.Engine == nil || ini.Synchronising == nil {
			return nil, fmt.Errorf("%w: network case without engine or synchronising", ErrInput)
		}
		switch *ini.Engine {
		case "running":
		case "stopped":
			d.running = false
		default:
			return nil, fmt.Errorf("%w: engine %q", ErrInput, *ini.Engine)
		}
		d.synchronising = *ini.Synchronising
		d.tr = &fakeTransport{}
		for _, p := range ini.Peers {
			if len(p) != 20 {
				return nil, fmt.Errorf("%w: peer of %d bytes", ErrInput, len(p))
			}
			d.tr.peers = append(d.tr.peers, types.Address(p))
		}
		if d.dedup, err = transport.NewDedup(d.tr, transport.DedupOptions{Self: self}); err != nil {
			return nil, err
		}
	} else if ini.Engine != nil || ini.Synchronising != nil || ini.Peers != nil {
		return nil, fmt.Errorf("%w: network fields in a state machine case", ErrInput)
	}
	return d, nil
}

func hashSet(hs []hexb) map[types.Hash]bool {
	m := make(map[types.Hash]bool, len(hs))
	for _, h := range hs {
		m[types.Hash(h)] = true
	}
	return m
}

func (d *driver) run(steps []stepInput) (any, error) {
	var start any
	d.stepIdx = -1
	if d.running {
		d.rec = newRecord()
		d.env.rec = d.rec
		if err := d.step(consensus.Start{}); err != nil {
			return nil, err
		}
		start = d.finish(false)
	}
	out := make([]any, 0, len(steps))
	for i, s := range steps {
		d.stepIdx = i
		d.rec = newRecord()
		d.env.rec = d.rec
		if err := d.do(s); err != nil {
			return nil, fmt.Errorf("step %d (%s): %w", i, s.Kind, err)
		}
		out = append(out, d.finish(!d.running))
	}
	return obj{"start": start, "steps": out}, nil
}

// finish renders the current record.
func (d *driver) finish(stopped bool) any {
	if !stopped {
		d.rec.state = varsOut(d.state.Vars())
	}
	return d.rec.out(d.network, stopped)
}

// step feeds one input to the core and applies its outputs, then feeds the
// BroadcastFailed inputs of refused signatures.
func (d *driver) step(in consensus.Input) error {
	if err := d.apply(d.state.Step(d.env, in)); err != nil {
		return err
	}
	for len(d.failed) > 0 {
		in := d.failed[0]
		d.failed = d.failed[1:]
		if err := d.apply(d.state.Step(d.env, in)); err != nil {
			return err
		}
	}
	return nil
}

func (d *driver) do(s stepInput) error {
	switch s.Kind {
	case "message":
		code, err := stepCode(s)
		if err != nil {
			return err
		}
		if !d.running {
			return nil
		}
		return d.step(consensus.Message{Code: codec.Code(code), Payload: s.Payload, Peer: d.self})
	case "backlog":
		code, err := stepCode(s)
		if err != nil {
			return err
		}
		if !d.running {
			return nil
		}
		return d.backlog(codec.Code(code), s.Payload)
	case "request":
		if !d.running {
			return nil
		}
		b, err := codec.DecodeBlock(s.Block)
		if err != nil {
			return fmt.Errorf("%w: block: %v", ErrInput, err)
		}
		d.take(func(in consensus.Input) bool {
			r, ok := in.(consensus.Request)
			if !ok {
				return false
			}
			enc, err := codec.EncodeBlock(r.Block)
			return err == nil && bytes.Equal(enc, s.Block)
		})
		return d.step(consensus.Request{Block: b})
	case "round_timeout":
		return d.roundTimeout(s)
	case "retry_timeout":
		return d.retryTimeout(s)
	case "future_timeout":
		return d.futureTimeout(s)
	case "stop":
		if !d.running {
			return nil
		}
		err := d.step(consensus.Stop{})
		d.running = false
		d.queue = nil
		for _, ts := range d.timers { //wbft:unordered every timer is marked
			for _, t := range ts {
				t.live = false
			}
		}
		return err
	case "start":
		if d.running {
			return nil
		}
		d.running = true
		return d.step(consensus.Start{})
	case "head":
		b, err := codec.DecodeBlock(s.Block)
		if err != nil {
			return fmt.Errorf("%w: block: %v", ErrInput, err)
		}
		if s.Notify == nil {
			return fmt.Errorf("%w: head step without notify", ErrInput)
		}
		d.env.head = b
		if *s.Notify && d.running {
			return d.step(consensus.NewHead{Header: b.Header})
		}
		return nil
	case "frame":
		if !d.network {
			return fmt.Errorf("%w: frame step in a state machine case", ErrInput)
		}
		return d.frame(s)
	}
	return fmt.Errorf("%w: step kind %q", ErrInput, s.Kind)
}

func stepCode(s stepInput) (uint64, error) {
	if s.Code == nil {
		return 0, fmt.Errorf("%w: %s step without code", ErrInput, s.Kind)
	}
	return s.Code.uint64()
}

// take removes and returns the first queued event that match accepts.
func (d *driver) take(match func(consensus.Input) bool) (consensus.Input, bool) {
	for i, in := range d.queue {
		if match(in) {
			d.queue = append(d.queue[:i], d.queue[i+1:]...)
			return in, true
		}
	}
	return nil, false
}

// backlog processes the scheduled replay whose encoding is payload. A replay
// the core did not schedule is processed as well, with the signers recovered
// from the payload.
func (d *driver) backlog(code codec.Code, payload []byte) error {
	in, ok := d.take(func(in consensus.Input) bool {
		r, ok := in.(consensus.Replay)
		if !ok || r.Msg.Msg.Code != code {
			return false
		}
		enc, err := r.Msg.Encode()
		return err == nil && bytes.Equal(enc, payload)
	})
	if ok {
		return d.step(in)
	}
	v, err := consensus.Recover(code, payload, nil)
	if err != nil {
		return nil // an undecodable replay is never scheduled; nothing happens
	}
	return d.step(consensus.Replay{Msg: v})
}

func (d *driver) timerAt(kind consensus.TimerKind, s stepInput) (*timerRec, error) {
	i, err := s.Timer.uint64()
	if err != nil {
		return nil, err
	}
	ts := d.timers[kind]
	if i >= uint64(len(ts)) {
		return nil, fmt.Errorf("%w: %s timer %d was never armed", ErrInput, kind, i)
	}
	return ts[i], nil
}

func (d *driver) roundTimeout(s stepInput) error {
	if s.Timer == nil {
		ts := d.timers[consensus.RoundTimer]
		if !d.running || len(ts) == 0 {
			return nil
		}
		t := ts[len(ts)-1]
		t.live = false
		return d.step(consensus.Timeout{Kind: consensus.RoundTimer, Gen: t.gen})
	}
	t, err := d.timerAt(consensus.RoundTimer, s)
	if err != nil || !t.live || !d.running {
		return err
	}
	t.live = false
	return d.step(consensus.Timeout{Kind: consensus.RoundTimer, Gen: t.gen})
}

func (d *driver) retryTimeout(s stepInput) error {
	if s.Round == nil {
		return fmt.Errorf("%w: retry_timeout without round", ErrInput)
	}
	r, err := types.RoundFromBig(&s.Round.Int)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	var gen uint64
	if s.Timer != nil {
		t, err := d.timerAt(consensus.RetryTimer, s)
		if err != nil || !t.live || !d.running {
			return err
		}
		t.live = false
		gen = t.gen
	}
	if !d.running {
		return nil
	}
	return d.step(consensus.Timeout{Kind: consensus.RetryTimer, Round: r, Gen: gen})
}

func (d *driver) futureTimeout(s stepInput) error {
	if s.Timer == nil {
		return fmt.Errorf("%w: future_timeout without timer", ErrInput)
	}
	t, err := d.timerAt(consensus.FutureTimer, s)
	if err != nil {
		return err
	}
	d.env.released[t.digest] = true
	if !t.live || !d.running {
		return nil
	}
	t.live = false
	return d.step(consensus.Timeout{Kind: consensus.FutureTimer, Gen: t.gen})
}

// apply executes the outputs of one Step in order.
func (d *driver) apply(outs []consensus.Output) error {
	for _, o := range outs {
		switch o := o.(type) {
		case consensus.Broadcast:
			if err := d.broadcast(o); err != nil {
				return err
			}
		case consensus.Relay:
			if d.network {
				d.rec.relayTo = addrList(d.dedup.Gossip(o.Validators, uint64(o.Code), o.Payload, event.CauseRelay))
			}
		case consensus.Schedule:
			d.queue = append(d.queue, o.In)
			switch in := o.In.(type) {
			case consensus.Replay:
				enc, err := in.Msg.Encode()
				if err != nil {
					return err
				}
				d.rec.scheduled = append(d.rec.scheduled, scheduledRec{
					source: in.Msg.Source,
					value:  obj{"kind": "backlog", "code": decU(uint64(in.Msg.Msg.Code)), "payload": hexOut(enc)},
				})
			case consensus.Request:
				enc, err := codec.EncodeBlock(in.Block)
				if err != nil {
					return err
				}
				d.rec.scheduled = append(d.rec.scheduled, scheduledRec{request: true, value: obj{"kind": "request", "block": hexOut(enc)}})
			}
		case consensus.ArmTimer:
			for _, t := range d.timers[o.Kind] {
				t.live = false
			}
			d.timers[o.Kind] = append(d.timers[o.Kind], &timerRec{gen: o.Gen, live: true, digest: o.Digest})
			t := obj{"kind": o.Kind.String()}
			switch o.Kind {
			case consensus.RetryTimer:
				t["round"] = o.Round.String()
			default:
				t["sequence"] = o.View.Sequence.String()
				t["round"] = o.View.Round.String()
			}
			d.rec.timers = append(d.rec.timers, t)
		case consensus.CancelTimers:
			for _, k := range o.Kinds {
				for _, t := range d.timers[k] {
					t.live = false
				}
			}
		case consensus.RequestBuild:
			d.rec.newRound = append(d.rec.newRound, o.Round.String())
		case consensus.Outcome:
			if o.Check != consensus.ClassNone {
				d.rec.check = o.Check.String()
			}
			d.rec.relay = o.Relayed
		case consensus.Commit, consensus.Event:
		}
	}
	return nil
}

// broadcast signs an own message as the node key does and records it.
func (d *driver) broadcast(b consensus.Broadcast) error {
	m := *b.Msg
	if d.signer != nil {
		sig, err := d.signer.SignVote(privval.VoteRequest{Msg: b.Msg, SealData: b.SealData, BadBlockReleased: b.BadBlockReleased})
		if err != nil {
			if !privval.IsRefusal(err) {
				return err
			}
			if d.opts.Refused != nil {
				d.opts.Refused(d.stepIdx, b.Msg, err)
			}
			d.failed = append(d.failed, consensus.BroadcastFailed{Code: m.Code, View: m.View})
			return nil
		}
		m.Seal, m.Signature = sig.Seal, sig.Signature
	} else {
		if b.SealData != nil {
			m.Seal = d.blsKey.Sign(b.SealData).Bytes()
		}
		p, err := codec.SigningPayload(&m, false, nil)
		if err != nil {
			return err
		}
		if m.Signature, err = ecdsa.SignData(p, d.key); err != nil {
			return err
		}
	}
	o, err := messageOut(&m)
	if err != nil {
		return err
	}
	if d.network {
		payload, err := codec.EncodeMessage(&m)
		if err != nil {
			return err
		}
		o["to"] = addrList(d.dedup.Broadcast(b.Validators, uint64(m.Code), payload, event.CauseBroadcast))
	}
	d.rec.sent = append(d.rec.sent, o)
	return nil
}

// frame processes an istanbul frame from a peer: the size limit, the
// engine-stopped rule, the frame stage, the caches and the core.
func (d *driver) frame(s stepInput) error {
	code, err := stepCode(s)
	if err != nil {
		return err
	}
	if len(s.Peer) != 20 {
		return fmt.Errorf("%w: frame peer of %d bytes", ErrInput, len(s.Peer))
	}
	peer := types.Address(s.Peer)
	payload := []byte(s.Payload)
	var data []byte
	var deliver uint64
	switch {
	case len(payload) > transport.MaxFramePayload:
		if d.opts.Frame == nil {
			return ErrUnsupported
		}
		act := transport.FrameDisconnect
		if _, _, a, _ := d.opts.Frame(code, payload); a != transport.FrameDeliver {
			act = a
		}
		d.rec.outcome = string(act.Outcome())
		return nil
	case !d.running && transport.IsConsensusCode(code):
		d.rec.outcome = string(transport.StoppedEngineAction(d.synchronising).Outcome())
		return nil
	case d.opts.Frame != nil:
		var act FrameAction
		data, deliver, act, _ = d.opts.Frame(code, payload)
		if act != transport.FrameDeliver {
			d.rec.outcome = string(act.Outcome())
			return nil
		}
	case code >= transport.CodeFirst && code <= transport.CodeLast && len(payload) > 0:
		data, deliver = payload, code
	default:
		return ErrUnsupported
	}
	if !d.running {
		// A delivered frame of a non-consensus code cannot reach here.
		return nil
	}
	key := codec.DedupKey(data)
	d.rec.dedupKey = hashOut(key)
	if d.dedup.SeenInbound(peer, deliver, data) {
		d.rec.outcome = string(event.DropSilent)
		return nil
	}
	if err := d.step(consensus.Message{Code: codec.Code(deliver), Payload: data, Peer: peer}); err != nil {
		return err
	}
	if d.rec.relay == true {
		d.rec.outcome = string(event.Accept)
	} else {
		d.rec.outcome = string(event.Ignore)
		if d.rec.relay == nil {
			d.rec.relay = false
		}
	}
	return nil
}

// env answers the core's Env calls with the case's application answers.
type env struct {
	head         *types.Block
	vs           *validator.Set
	invalid      map[types.Hash]bool
	future       map[types.Hash]bool
	released     map[types.Hash]bool
	bad          map[types.Hash]bool
	finalizeFail bool
	rec          *record
}

var errInvalidProposal = errors.New("stepdriver: the case marks the proposal invalid")

func (e *env) Head() consensus.HeadInfo {
	return consensus.HeadInfo{Header: e.head.Header, Proposer: types.ProposerOf(e.head.Header)}
}

func (e *env) ValidatorsAt(types.Height, types.Hash) (*validator.Set, error) { return e.vs, nil }

func (e *env) ValidateProposal(b *types.Block) (time.Duration, error) {
	h := codec.BlockHash(b.Header)
	if e.invalid[h] {
		return 0, errInvalidProposal
	}
	if e.future[h] && !e.released[h] {
		return time.Second, fmt.Errorf("stepdriver: %w", header.ErrFutureBlock)
	}
	return 0, nil
}

func (e *env) IsBadBlock(h types.Hash) bool { return e.bad[h] }

var errFinalize = errors.New("stepdriver: the case makes finalize fail")

func (e *env) CommitHeader(b *types.Block, round types.Round, _ *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error) {
	f := obj{
		"proposal":        hashOut(codec.BlockHash(b.Header)),
		"round":           round.String(),
		"prepared_seals":  sealsOut(prepared),
		"committed_seals": sealsOut(committed),
		"result":          "ok",
	}
	if e.rec != nil {
		e.rec.finalized = f
	}
	if e.finalizeFail {
		f["result"] = "fail"
		return nil, errFinalize
	}
	out, err := header.CommitHeader(b, round, prepared, committed)
	if err != nil {
		f["result"] = "fail"
		return nil, err
	}
	return out, nil
}

// fakeTransport has the case's peers attached and discards what is sent.
type fakeTransport struct{ peers []types.Address }

func (t *fakeTransport) Send(peers []types.Address, _ uint64, _ []byte) []transport.SendResult {
	return make([]transport.SendResult, len(peers))
}
func (t *fakeTransport) SetReceiver(transport.Receiver)         {}
func (t *fakeTransport) PeerEvents() <-chan transport.PeerEvent { return nil }
func (t *fakeTransport) Disconnect(types.Address, string)       {}
func (t *fakeTransport) Peers() []transport.PeerInfo {
	out := make([]transport.PeerInfo, len(t.peers))
	for i, p := range t.peers {
		out[i] = transport.PeerInfo{Addr: p}
	}
	return out
}
