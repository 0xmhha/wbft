package node

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

type preparedLifecycleClock struct {
	mu     sync.Mutex
	at     time.Duration
	timers []*preparedLifecycleTimer
}

type preparedLifecycleTimer struct {
	clock   *preparedLifecycleClock
	due     time.Duration
	fn      func()
	stopped bool
}

func (c *preparedLifecycleClock) Now() time.Time      { return time.Unix(1700000000, 0).Add(c.Mono()) }
func (c *preparedLifecycleClock) Mono() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *preparedLifecycleClock) AfterFunc(d time.Duration, fn func()) runner.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &preparedLifecycleTimer{clock: c, due: c.at + d, fn: fn}
	c.timers = append(c.timers, timer)
	return timer
}
func (t *preparedLifecycleTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *preparedLifecycleClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at += d
	var ready []func()
	for _, timer := range c.timers {
		if !timer.stopped && timer.due <= c.at {
			timer.stopped = true
			ready = append(ready, timer.fn)
		}
	}
	c.mu.Unlock()
	for _, fn := range ready {
		fn()
	}
}

type preparedLifecycleFrame struct {
	code    codec.Code
	payload []byte
}
type preparedLifecycleTransport struct {
	mu       sync.Mutex
	receiver transport.Receiver
	peers    []transport.PeerInfo
	self     types.Address
	dir      string
	frames   []preparedLifecycleFrame
	errors   []error
}

func (p *preparedLifecycleTransport) SetReceiver(r transport.Receiver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.receiver = r
}
func (*preparedLifecycleTransport) PeerEvents() <-chan transport.PeerEvent { return nil }
func (p *preparedLifecycleTransport) Peers() []transport.PeerInfo {
	return append([]transport.PeerInfo(nil), p.peers...)
}
func (*preparedLifecycleTransport) Disconnect(types.Address, string) {}
func preparedFrameAuthor(code codec.Code, raw []byte) (types.Address, error) {
	m, err := codec.DecodeMessage(code, raw)
	if err != nil {
		return types.Address{}, err
	}
	b, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		return types.Address{}, err
	}
	return ecdsa.RecoverDataSigner(b, m.Signature)
}
func (p *preparedLifecycleTransport) Send(peers []types.Address, code uint64, raw []byte) []transport.SendResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	// This fixture queues normal protocol frames. Delivery is explicitly
	// ordered by the test; it never corrupts, replaces or drops a frame.
	if len(peers) > 0 {
		p.frames = append(p.frames, preparedLifecycleFrame{codec.Code(code), bytes.Clone(raw)})
		if author, err := preparedFrameAuthor(codec.Code(code), raw); err == nil && author == p.self && (codec.Code(code) == codec.CodePrepare || codec.Code(code) == codec.CodeCommit) {
			own, err := preparedStoredOwn(p.dir)
			state, stateErr := (fsys.OS{}).ReadFile(filepath.Join(p.dir, "privval", "state"))
			if err != nil || stateErr != nil || len(state) == 0 || !bytes.Equal(own[codec.Code(code)], raw) {
				p.errors = append(p.errors, fmt.Errorf("own vote reached transport before stored state: %v %v", err, stateErr))
			}
		}
	}
	return make([]transport.SendResult, len(peers))
}
func (p *preparedLifecycleTransport) own(code codec.Code) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out [][]byte
	for _, f := range p.frames {
		a, err := preparedFrameAuthor(f.code, f.payload)
		if err == nil && a == p.self && f.code == code {
			out = append(out, bytes.Clone(f.payload))
		}
	}
	return out
}
func (p *preparedLifecycleTransport) offer(t *testing.T, peer types.Address, m *codec.Message, clock *preparedLifecycleClock) {
	t.Helper()
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	receiver := p.receiver
	p.mu.Unlock()
	if receiver == nil || !receiver.Offer(transport.Inbound{Peer: peer, Code: uint64(m.Code), Payload: raw, RecvMono: clock.Mono()}) {
		t.Fatal("normal frame was not queued")
	}
}

func preparedStoredOwn(dir string) (map[codec.Code][]byte, error) {
	records, _, err := wal.ReadAll(fsys.OS{}, filepath.Join(dir, "wal"))
	if err != nil {
		return nil, err
	}
	out := map[codec.Code][]byte{}
	for _, r := range records {
		if r.Format != 1 || r.Kind != 4 {
			continue
		}
		var own struct {
			Code       uint64
			Payload    []byte
			Refused    uint64
			Seq, Round *big.Int
		}
		if err := rlp.DecodeStrict(r.Body, &own); err != nil {
			return nil, err
		}
		if own.Refused != 0 {
			return nil, fmt.Errorf("unexpected normal signer refusal")
		}
		if codec.Code(own.Code) != codec.CodePrepare && codec.Code(own.Code) != codec.CodeCommit {
			continue
		}
		m, err := codec.DecodeMessage(codec.Code(own.Code), own.Payload)
		if err != nil {
			return nil, err
		}
		if m.View.Sequence.CmpUint64(1) == 0 && m.View.Round.IsZero() {
			out[codec.Code(own.Code)] = bytes.Clone(own.Payload)
		}
	}
	return out, nil
}

func preparedLifecycleWait(t *testing.T, clock *preparedLifecycleClock, why string, ready func() bool) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		clock.advance(0)
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("normal prepared lifecycle did not reach " + why)
}

func TestNormalPreparedNodeLifecycle(t *testing.T) {
	for _, mode := range []string{"engine", "reopen"} {
		t.Run(mode, func(t *testing.T) {
			keys := [][]byte{testKey(0), testKey(1), testKey(2), testKey(3)}
			raw, genesis := testGenesis(t, keys...)
			genesis.Header.Time = 1699999999
			a := newTestApp(raw, genesis)
			dir := t.TempDir()
			clock := &preparedLifecycleClock{}
			var peers []transport.PeerInfo
			var signers []*privval.FileSigner
			for i, key := range keys {
				fs := fsys.NewMem()
				if err := fs.MkdirAll("/sign", 0700); err != nil {
					t.Fatal(err)
				}
				s, err := privval.NewKeySignerWithOptions(privval.Options{FS: fs}, key, "/sign/state")
				if err != nil {
					t.Fatal(err)
				}
				signers = append(signers, s)
				if i > 0 {
					peers = append(peers, transport.PeerInfo{Addr: s.Address(), Caps: []string{"istanbul/100"}})
				}
			}
			var n *Node
			var wire *preparedLifecycleTransport
			var wires []*preparedLifecycleTransport
			events := &syncBuffer{}
			start := func(lifetime int) {
				wire = &preparedLifecycleTransport{self: signers[0].Address(), peers: peers, dir: dir}
				wires = append(wires, wire)
				var err error
				// No optional improvement enables this default local protection.
				n, err = New(Config{DataDir: dir, RunID: fmt.Sprintf("prepared-lifetime-%d", lifetime)}, Deps{App: a, Authority: a, Transport: wire, Events: events, key: keys[0], clock: clock})
				if err != nil {
					t.Fatal(err)
				}
				a.cons = n.Consensus()
				if err := n.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			start(1)
			t.Cleanup(func() {
				if n != nil && n.running() {
					stop(t, n)
				}
			})
			preparedLifecycleWait(t, clock, "own proposal and PREPARE", func() bool { return len(wire.own(codec.CodePreprepare)) > 0 && len(wire.own(codec.CodePrepare)) > 0 })
			proposal, err := codec.DecodeMessage(codec.CodePreprepare, wire.own(codec.CodePreprepare)[0])
			if err != nil {
				t.Fatal(err)
			}
			block := proposal.Proposal
			hash := codec.BlockHash(block.Header)
			if block.Header.ParentHash != codec.BlockHash(genesis.Header) || proposal.View.Sequence.CmpUint64(1) != 0 || !proposal.View.Round.IsZero() {
				t.Fatal("normal proposal identity changed")
			}
			for _, signer := range signers[1:3] {
				m := &codec.Message{Code: codec.CodePrepare, View: proposal.View, Digest: hash}
				sig, err := signer.SignVote(privval.VoteRequest{Msg: m, SealData: codec.SealData(block.Header, 0, types.PrepareSeal)})
				if err != nil {
					t.Fatal(err)
				}
				m.Signature, m.Seal = sig.Signature, sig.Seal
				wire.offer(t, signer.Address(), m, clock)
			}
			preparedLifecycleWait(t, clock, "actual prepared quorum and own COMMIT", func() bool {
				s := n.Runner().Snapshot()
				return s != nil && s.State == consensus.Prepared && len(wire.own(codec.CodeCommit)) > 0
			})
			before, err := preparedStoredOwn(dir)
			if err != nil || len(before) != 2 {
				t.Fatal("stored normal PREPARE/COMMIT missing", err)
			}
			stored, err := (fsys.OS{}).ReadFile(filepath.Join(dir, "privval", "state"))
			if err != nil {
				t.Fatal(err)
			}
			control := func(state app.SyncState, after uint64, want string) *journal.SyncRec {
				a.cons.OnSyncState(state)
				var found *journal.SyncRec
				preparedLifecycleWait(t, clock, "processed sync control", func() bool {
					if err := n.journal.Sync(); err != nil {
						t.Fatal(err)
					}
					records, err := journal.ReadAll(fsys.OS{}, filepath.Join(dir, journalDir))
					if err != nil {
						t.Fatal(err)
					}
					for _, record := range records {
						if r, ok := record.Body.(*journal.SyncRec); ok && r.Stage == "processed" && r.Operation > after {
							found = r
							return true
						}
					}
					return false
				})
				if found.Action != want || found.Failed || found.SequenceExhausted {
					t.Fatal("normal control policy changed", found)
				}
				if want != "none" && (!found.EventsAvailable || found.EventAfter <= found.EventBefore || found.RunningBefore == found.RunningAfter) {
					t.Fatal("actual engine control boundary missing", found)
				}
				return found
			}
			beforeSends := map[codec.Code]int{}
			if mode == "engine" {
				for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
					beforeSends[code] = len(wire.own(code))
				}
				stopped := control(app.SyncState{Syncing: true}, 0, "stop")
				if stopped.FirstBefore || stopped.FirstAfter {
					t.Fatal("initial sync policy changed")
				}
				started := control(app.SyncState{}, stopped.Operation, "start")
				if started.FirstBefore || started.FirstAfter {
					t.Fatal("a failed sync became a successful first sync")
				}
				success := control(app.SyncState{Success: true}, started.Operation, "none")
				guarded := control(app.SyncState{Syncing: true}, success.Operation, "none")
				if success.FirstBefore || !success.FirstAfter || !guarded.FirstBefore || !guarded.FirstAfter || !guarded.RunningAfter {
					t.Fatal("first-success guard changed", success, guarded)
				}
				control(app.SyncState{Success: true}, guarded.Operation, "none")
			} else {
				stop(t, n)
				start(2)
			}
			preparedLifecycleWait(t, clock, "restored prepared view", func() bool {
				s := n.Runner().Snapshot()
				return s != nil && s.Running && s.State == consensus.Prepared && s.View.Cmp(proposal.View) == 0
			})
			after, err := preparedStoredOwn(dir)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("normal restart changed stored own votes", err)
			}
			resent := map[codec.Code]int{}
			for _, code := range []codec.Code{codec.CodePrepare, codec.CodeCommit} {
				old, err := codec.DecodeMessage(code, before[code])
				if err != nil {
					t.Fatal(err)
				}
				kind := types.PrepareSeal
				if code == codec.CodeCommit {
					kind = types.CommitSeal
				}
				reused, err := n.signer.SignVote(privval.VoteRequest{Msg: old, SealData: codec.SealData(block.Header, 0, kind)})
				if err != nil || !reused.Reused || !bytes.Equal(reused.Signature, old.Signature) || !bytes.Equal(reused.Seal, old.Seal) {
					t.Fatal("same normal vote did not reuse stored signature and seal", code, err)
				}
				sentAfter := wire.own(code)
				if len(sentAfter) < beforeSends[code] {
					t.Fatal("normal transport observation lost its prefix")
				}
				resent[code] = len(sentAfter) - beforeSends[code]
				for _, sent := range sentAfter[beforeSends[code]:] {
					if !bytes.Equal(sent, before[code]) {
						t.Fatal("actual own retransmission changed bytes", code)
					}
				}
			}
			state, err := (fsys.OS{}).ReadFile(filepath.Join(dir, "privval", "state"))
			if err != nil || !bytes.Equal(stored, state) {
				t.Fatal("normal replay/reuse rewrote signer state", err)
			}
			clock.advance(2 * time.Second)
			preparedLifecycleWait(t, clock, "normal prepared round change", func() bool { return len(wire.own(codec.CodeRoundChange)) > 0 })
			rc, err := codec.DecodeMessage(codec.CodeRoundChange, wire.own(codec.CodeRoundChange)[0])
			if err != nil || rc.PreparedRound == nil || !rc.PreparedRound.IsZero() || rc.PreparedDigest != hash || len(rc.Prepares) != 3 || rc.View.Round.Cmp(types.RoundFromUint64(1)) != 0 {
				t.Fatal("normal round change lost prepared identity or certificate", err)
			}
			for _, prepare := range rc.Prepares {
				if prepare.Digest != hash || prepare.View.Cmp(proposal.View) != 0 {
					t.Fatal("prepared certificate changed view or block")
				}
			}
			stop(t, n)
			for lifetime, sentWire := range wires {
				sentWire.mu.Lock()
				sendErrors := append([]error(nil), sentWire.errors...)
				sentWire.mu.Unlock()
				if len(sendErrors) != 0 {
					t.Fatal("persistence before send", lifetime, sendErrors)
				}
			}
			reader, err := journal.OpenReader(fsys.OS{}, filepath.Join(dir, journalDir))
			if err != nil {
				t.Fatal(err)
			}
			preparedRuns := map[string]bool{}
			err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: appBlocks{a}, WithVars: true}, func(s stepdriver.StepResult) error {
				if !s.Match {
					return fmt.Errorf("normal replay mismatch: %s/%d/%d", s.WriterRun, s.EngineRun, s.Step)
				}
				v := s.Vars
				if v != nil && v.State == consensus.Prepared && v.View.Cmp(proposal.View) == 0 && v.LockedBlock != nil {
					if *v.LockedBlock != hash || v.LockedRound == nil || !v.LockedRound.IsZero() || len(v.Certificate) != 3 {
						return fmt.Errorf("normal prepared state changed in %s/%d", s.WriterRun, s.EngineRun)
					}
					preparedRuns[fmt.Sprintf("%s/%d", s.WriterRun, s.EngineRun)] = true
				}
				return nil
			})
			if err != nil || len(preparedRuns) != 2 {
				t.Fatal("both normal engine lifetimes did not retain prepared state", err, preparedRuns)
			}
			t.Logf("normal lifecycle=%s OS_reopen=%t prepared_runs=%d stored_own_votes=%d postrestart_prepare_sends=%d postrestart_commit_sends=%d", mode, mode == "reopen", len(preparedRuns), len(after), resent[codec.CodePrepare], resent[codec.CodeCommit])
		})
	}
}
