package sim

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// Validator is the key of one simulated node. Tests supply the keys; the
// simulator does not make any.
type Validator struct {
	ECDSA []byte // 32-byte secret key; test keys only

	address types.Address
	blsPub  []byte
}

// Address returns the address of the key.
func (v Validator) Address() types.Address { return v.address }

// NodeSpec configures one node.
type NodeSpec struct {
	// Options are the core options; the simulator sets Config and Self.
	Options consensus.Options
	// Profile is recorded in the journal ("compat" or "improved").
	Profile string
	// ReplayWAL replays the write-ahead log when the node starts.
	ReplayWAL bool
	// ClockSkew moves the node's wall clock.
	ClockSkew time.Duration
	// TakeoverGuard sets the sign floor at start when the sign state is
	// empty and the head is above genesis.
	TakeoverGuard bool
}

// Link is a directed link; pairs without a link use Scenario.DefaultLink.
type Link struct {
	From, To types.Address
	Delay    []time.Duration // samples, drawn with the scenario seed
	Loss     float64         // probability in [0, 1)
}

// Partition cuts links during [From, To).
type Partition struct {
	From, To time.Duration
	Cut      [][2]types.Address
}

// Node actions of a NodeEvent.
const (
	ActionStop    = "stop"    // clean stop of the engine and the node
	ActionCrash   = "crash"   // kill: only what was synced survives
	ActionRestart = "restart" // start a stopped or crashed node
)

// NodeEvent stops, crashes or restarts a node at a time.
type NodeEvent struct {
	At     time.Duration
	Node   types.Address
	Action string
}

// AppModel is the timing of the fake application.
type AppModel struct {
	BuildDelay  []time.Duration // block assembly time samples
	ImportDelay []time.Duration // import time samples
	// SlowImport gives the import time of some blocks at some nodes.
	SlowImport []SlowImport
	// BadProposals makes the blocks a proposer builds at a height fail
	// execution at every node (the bad-block path).
	BadProposals []BadProposal
}

// SlowImport is the import time of the block of Height at Node (every
// node when Node is zero).
type SlowImport struct {
	Node   types.Address
	Height uint64
	Delay  time.Duration
}

// BadProposal names a proposer and a height whose blocks fail execution.
type BadProposal struct {
	Height   uint64
	Proposer types.Address
}

// EpochChange sets the candidates recorded by the epoch block Block: the
// indices into Scenario.Validators of the next epoch's validators.
type EpochChange struct {
	Block      uint64
	Candidates []int
}

// Params are the consensus parameters of the chain.
type Params struct {
	RequestTimeoutSeconds    uint64
	BlockPeriodSeconds       uint64
	EpochLength              uint64
	MaxRequestTimeoutSeconds *uint64
}

// Stop ends a simulation: when every running honest node reached Height,
// or at Duration of simulated time.
type Stop struct {
	Height   uint64
	Duration time.Duration
}

// Fault crashes a node at the Hit-th time (from 0) it passes the fault
// point Point, and restarts it RestartAfter later. It has an effect only in
// builds with the tag wbft_faults.
type Fault struct {
	Node         types.Address
	Point        string
	Hit          int
	RestartAfter time.Duration
}

// Disk fault kinds.
const (
	// DiskTruncateWAL cuts the newest write-ahead log segment at a random
	// byte.
	DiskTruncateWAL = "wal_truncate"
	// DiskCorruptWAL flips a byte in a random write-ahead log segment.
	DiskCorruptWAL = "wal_corrupt"
	// DiskPartialSignState cuts the sign state file in half.
	DiskPartialSignState = "privval_partial"
)

// DiskFault damages the files of a node that is down at At.
type DiskFault struct {
	At   time.Duration
	Node types.Address
	Kind string
}

// Scenario is one simulation. The same Scenario, including Seed, always
// yields the same outputs.
type Scenario struct {
	Name string
	Seed int64
	// Validators are the keys of all nodes, in node order. The first
	// Genesis of them are the genesis validators (all when zero).
	Validators []Validator
	Genesis    int
	// Nodes configure the nodes by index; missing entries use
	// DefaultNode.
	Nodes       []NodeSpec
	Params      Params
	DefaultLink Link
	Links       []Link
	Partitions  []Partition
	Schedule    []NodeEvent
	App         AppModel
	Epochs      []EpochChange
	Adversaries []Adversary
	Faults      []Fault
	Disk        []DiskFault
	Until       Stop
	// NoProgress disables the progress check.
	NoProgress bool
}

// DefaultNode is the node of Part 1: reference behaviour with the two
// restart-safety rules (the round-0 proposal guard of the core and the
// write-ahead log replay; the sign rules of privval are always on).
func DefaultNode() NodeSpec {
	return NodeSpec{Options: consensus.Options{Improvements: consensus.RestartSafety}, Profile: "compat", ReplayWAL: true}
}

// NewValidator returns the validator of a 32-byte test key.
func NewValidator(secret []byte) (Validator, error) {
	k, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		return Validator{}, err
	}
	b, err := bls.DeriveSecretKey(secret)
	if err != nil {
		return Validator{}, err
	}
	return Validator{ECDSA: append([]byte(nil), secret...), address: ecdsa.Address(k), blsPub: b.PublicKey().Bytes()}, nil
}

// Output names the directories a run writes to; empty names write nothing.
type Output struct {
	// EventsDir receives one events-<run>.jsonl per node incarnation.
	EventsDir string
	// JournalDir receives one directory per node with its message journal
	// and chain.rlp, the longest chain of the run.
	JournalDir string
}

// Violation is a failed property.
type Violation struct {
	Kind   string // agreement, double_sign, progress, header, replay, lock_lost, refinalize, start
	Node   types.Address
	Detail string
}

func (v Violation) String() string { return fmt.Sprintf("%s at %x: %s", v.Kind, v.Node[:4], v.Detail) }

// Result is the outcome of a run.
type Result struct {
	Heads      []uint64          // final head per node
	Chain      []*types.Block    // longest chain of the run, from genesis
	Rounds     map[uint64]uint64 // round of each decided height
	Violations []Violation
	Evidence   int // EVIDENCE events written
	Crashes    int
	Replays    []runner.ReplayInfo
	Refinalize int                                 // blocks finalized again by the start-up handshake
	LockChecks int                                 // restored locks compared after a crash
	Damaged    int                                 // disk faults applied
	Journals   map[types.Address]map[string][]byte // journal files per node
	Events     map[string][]byte                   // event files by name
	SimTime    time.Duration
}

// ErrScenario reports an invalid scenario.
var ErrScenario = errors.New("sim: invalid scenario")

// Run executes the scenario on a manual clock.
func Run(ctx context.Context, sc Scenario, out Output) (*Result, error) {
	s, err := newSimulation(sc)
	if err != nil {
		return nil, err
	}
	if err := s.run(ctx); err != nil {
		return nil, err
	}
	res := s.result()
	if err := writeOutput(out, res); err != nil {
		return res, err
	}
	return res, nil
}

func writeOutput(out Output, res *Result) error {
	if out.EventsDir != "" {
		if err := os.MkdirAll(out.EventsDir, 0o700); err != nil {
			return err
		}
		for _, name := range sortedKeys(res.Events) {
			if err := os.WriteFile(filepath.Join(out.EventsDir, name), res.Events[name], 0o600); err != nil {
				return err
			}
		}
	}
	if out.JournalDir != "" {
		for _, a := range sortedAddrs(res.Journals) {
			dir := filepath.Join(out.JournalDir, fmt.Sprintf("%x", a[:]))
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			files := res.Journals[a]
			for _, name := range sortedKeys(files) {
				if err := os.WriteFile(filepath.Join(dir, name), files[name], 0o600); err != nil {
					return err
				}
			}
		}
		chain, err := EncodeChain(res.Chain)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out.JournalDir, "chain.rlp"), chain, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m { //wbft:unordered sorted below
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func sortedAddrs[V any](m map[types.Address]V) []types.Address {
	ks := make([]types.Address, 0, len(m))
	for k := range m { //wbft:unordered sorted below
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b types.Address) int { return strings.Compare(string(a[:]), string(b[:])) })
	return ks
}

// ReadJournalDir returns the node journal directories and the chain file of
// an output directory written by Run.
func ReadJournalDir(dir string) (nodes []string, chain []*types.Block, err error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range es {
		if e.IsDir() {
			nodes = append(nodes, filepath.Join(dir, e.Name()))
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "chain.rlp"))
	if err != nil {
		return nil, nil, err
	}
	chain, err = DecodeChain(b)
	return nodes, chain, err
}

// simulation is the state of one run.
type simulation struct {
	sc       Scenario
	l        loop
	rng      *rand.Rand
	cfg      *types.Config
	cfgJSON  []byte
	genesis  *types.Block
	nodes    []*node
	byAddr   map[types.Address]*node
	decided  map[uint64]types.Hash
	decBlock map[uint64]*types.Block
	rounds   map[uint64]uint64
	signed   map[signKey]types.Hash
	viol     []Violation
	crashes  int
	replays  []runner.ReplayInfo
	refinal  int
	locks    int
	evidence int
	damaged  int
	ctx      context.Context
}

type signKey struct {
	node       types.Address
	code       codec.Code
	seq, round string
}

func newSimulation(sc Scenario) (*simulation, error) {
	if len(sc.Validators) == 0 {
		return nil, fmt.Errorf("%w: no validators", ErrScenario)
	}
	for i := range sc.Validators {
		v, err := NewValidator(sc.Validators[i].ECDSA)
		if err != nil {
			return nil, fmt.Errorf("%w: validator %d: %v", ErrScenario, i, err)
		}
		sc.Validators[i] = v
	}
	if sc.Genesis == 0 {
		sc.Genesis = len(sc.Validators)
	}
	if sc.Params.RequestTimeoutSeconds == 0 {
		sc.Params.RequestTimeoutSeconds = 2
	}
	if sc.Params.BlockPeriodSeconds == 0 {
		sc.Params.BlockPeriodSeconds = 1
	}
	if sc.Params.EpochLength == 0 {
		sc.Params.EpochLength = 1 << 40
	}
	if len(sc.DefaultLink.Delay) == 0 {
		sc.DefaultLink.Delay = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	}
	if len(sc.App.BuildDelay) == 0 {
		sc.App.BuildDelay = []time.Duration{2 * time.Millisecond, 10 * time.Millisecond}
	}
	if len(sc.App.ImportDelay) == 0 {
		sc.App.ImportDelay = []time.Duration{2 * time.Millisecond, 10 * time.Millisecond}
	}
	if sc.Until.Duration == 0 {
		sc.Until.Duration = 5 * time.Minute
	}
	cj, err := chainConfigJSON(sc.Params, sc.Validators[:sc.Genesis])
	if err != nil {
		return nil, err
	}
	cfg, err := types.ParseChainConfig(cj)
	if err != nil {
		return nil, err
	}
	g, err := genesisBlock(cfg)
	if err != nil {
		return nil, err
	}
	s := &simulation{sc: sc, rng: rand.New(rand.NewPCG(uint64(sc.Seed), 0x5eed)), cfg: cfg, cfgJSON: cj, genesis: g,
		byAddr: map[types.Address]*node{}, decided: map[uint64]types.Hash{}, decBlock: map[uint64]*types.Block{},
		rounds: map[uint64]uint64{}, signed: map[signKey]types.Hash{}}
	s.decided[0] = codec.BlockHash(g.Header)
	s.decBlock[0] = g
	for i, v := range sc.Validators {
		spec := DefaultNode()
		if i < len(sc.Nodes) {
			spec = sc.Nodes[i]
		}
		n := newNode(s, i, v, spec)
		s.nodes = append(s.nodes, n)
		s.byAddr[v.address] = n
	}
	return s, nil
}

func (s *simulation) violate(kind string, node types.Address, format string, args ...any) {
	s.viol = append(s.viol, Violation{Kind: kind, Node: node, Detail: fmt.Sprintf(format, args...)})
}

// run starts the nodes, applies the schedule and advances time until the
// stop condition.
func (s *simulation) run(ctx context.Context) error {
	s.ctx = ctx
	for _, n := range s.nodes {
		n.start()
	}
	for _, ev := range s.sc.Schedule {
		ev := ev
		n := s.byAddr[ev.Node]
		if n == nil {
			return fmt.Errorf("%w: schedule names an unknown node", ErrScenario)
		}
		s.l.at(ev.At, func() {
			switch ev.Action {
			case ActionStop:
				n.stop()
			case ActionCrash:
				n.crash()
			case ActionRestart:
				if !n.alive {
					n.start()
				}
			}
		})
	}
	for _, a := range s.sc.Adversaries {
		s.startAdversary(a)
	}
	for _, d := range s.sc.Disk {
		d := d
		n := s.byAddr[d.Node]
		if n == nil {
			return fmt.Errorf("%w: disk fault names an unknown node", ErrScenario)
		}
		s.l.at(d.At, func() { n.damage(d.Kind) })
	}
	s.l.after(syncInterval, s.syncTick)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.pumpAll()
		if s.done() {
			return nil
		}
		t, ok := s.l.nextTime()
		if !ok || t > s.sc.Until.Duration {
			s.l.now = s.sc.Until.Duration
			break
		}
		s.l.runAt(t)
	}
	s.checkProgress()
	return nil
}

// pumpAll drives every live node until no node has anything left to do at
// the current time.
func (s *simulation) pumpAll() {
	for {
		progressed := false
		for _, n := range s.nodes {
			if n.pump() {
				progressed = true
			}
		}
		if !progressed {
			return
		}
	}
}

// done reports whether every running honest node reached the stop height.
func (s *simulation) done() bool {
	if s.sc.Until.Height == 0 {
		return false
	}
	for _, n := range s.nodes {
		if n.adversary || !n.expectedLive() {
			continue
		}
		if n.head() < s.sc.Until.Height {
			return false
		}
	}
	return true
}

func (s *simulation) checkProgress() {
	if s.sc.NoProgress || s.sc.Until.Height == 0 {
		return
	}
	for _, n := range s.nodes {
		if n.adversary || !n.expectedLive() {
			continue
		}
		if h := n.head(); h < s.sc.Until.Height {
			s.violate("progress", n.v.address, "head %d below %d at %s", h, s.sc.Until.Height, s.l.now)
		}
	}
}

// noteSigned records a signature of an honest node and reports two
// signatures for different values in one view.
func (s *simulation) noteSigned(n *node, m *codec.Message) {
	var d types.Hash
	switch m.Code {
	case codec.CodePrepare, codec.CodeCommit:
		d = m.Digest
	case codec.CodePreprepare:
		if m.Proposal == nil {
			return
		}
		d = codec.BlockHash(m.Proposal.Header)
	default:
		return
	}
	k := signKey{node: n.v.address, code: m.Code, seq: m.View.Sequence.String(), round: m.View.Round.String()}
	if old, ok := s.signed[k]; ok && old != d {
		s.violate("double_sign", n.v.address, "code %d view (%s, %s): %x and %x", m.Code, k.seq, k.round, old[:4], d[:4])
		return
	}
	s.signed[k] = d
}

// noteDecided records a block a node stored and checks agreement.
func (s *simulation) noteDecided(n *node, b *types.Block) {
	h := index(b.Header)
	hash := codec.BlockHash(b.Header)
	if old, ok := s.decided[h]; ok {
		if old != hash {
			s.violate("agreement", n.v.address, "height %d: %x, others %x", h, hash[:4], old[:4])
		}
		return
	}
	s.decided[h] = hash
	s.decBlock[h] = b
	if x, err := codec.DecodeExtra(b.Header); err == nil {
		s.rounds[h] = uint64(x.Round)
	}
}

func (s *simulation) result() *Result {
	res := &Result{Rounds: s.rounds, Violations: s.viol, Crashes: s.crashes, Replays: s.replays, Refinalize: s.refinal,
		LockChecks: s.locks, Damaged: s.damaged, Evidence: s.evidence, Journals: map[types.Address]map[string][]byte{}, Events: map[string][]byte{}, SimTime: s.l.now}
	for i := uint64(0); ; i++ {
		b := s.decBlock[i]
		if b == nil {
			break
		}
		res.Chain = append(res.Chain, b)
	}
	for _, n := range s.nodes {
		if n.alive && n.jw != nil {
			// A running node syncs its journal once a second; the end of
			// the run counts as such a moment.
			_ = n.jw.Sync()
		}
		res.Heads = append(res.Heads, n.head())
		files := map[string][]byte{}
		for name, data := range n.fs.Dump(journalDir) { //wbft:unordered result is a map
			files[filepath.Base(name)] = data
		}
		res.Journals[n.v.address] = files
		for name, data := range n.eventFiles { //wbft:unordered result is a map
			res.Events[name] = data.Bytes()
		}
	}
	return res
}
