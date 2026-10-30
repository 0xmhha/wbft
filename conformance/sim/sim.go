package sim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event/schema"
	"github.com/0xmhha/wbft/observe/logcat"
	"github.com/0xmhha/wbft/types"
	"io"
	"log/slog"
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
	// ValidatorHistory bounds the explicitly selected validator-start WAL
	// profile. It is copied and requires replay; nil uses its finite defaults.
	ValidatorHistory *runner.ValidatorHistoryLimits `json:",omitempty"`
	// Timing overrides only this node's timing parameters for all incarnations.
	// Nil fields inherit Scenario.Params; a zero maximum explicitly removes a cap.
	Timing *TimingParams `json:",omitempty"`
	// Processing declares an optional pre-dispatch receive/core service model.
	// Nil and all-zero samples preserve the original zero-cost manual loop.
	Processing *ProcessingProfile
	// WriteQueue opts into normal FIFO local-write service before link delivery.
	// Nil preserves the original transport. It does not enable a cache policy.
	WriteQueue *WriteQueueProfile `json:",omitempty"`
	// AcceptedCache is a diagnostic-only cache experiment. It requires normal
	// write queues on all endpoints and never enables functional journal replay.
	AcceptedCache *AcceptedCacheProfile `json:",omitempty"`
	// BuildQueuePolicy opts into a declared serial application worker. Empty
	// preserves the independent-request model used by existing scenarios.
	BuildQueuePolicy string
	// Sealing is required only by BuildQueueSealing. Its empty-body fake
	// executor and seeded actor selection are recorded with the node startup.
	Sealing *SealingProfile
	// BuildDoneResult explicitly selects the fake executor's return after Done:
	// failed models a cooperative executor, submitted an executor ignoring Done.
	// The sampled assembly return still owns the worker until its deadline.
	BuildDoneResult string
	// StartAfter delays this node's first incarnation; zero starts at time zero.
	StartAfter time.Duration
	// BuildDelay and ImportDelay override the shared application samples when
	// nonempty, preserving distinct recorded node timing distributions.
	BuildDelay  []time.Duration
	ImportDelay []time.Duration

	// Options are the core options; the simulator sets Config and Self.
	Options consensus.Options
	// Profile is recorded in the journal ("compat" or "improved").
	Profile string
	// ReplayWAL replays the write-ahead log when the node starts.
	ReplayWAL bool
	// NextHeight declares the bounded next-sequence receive lane. Nil preserves
	// the original receiver; enabled lanes require WAL replay and atomic work.
	NextHeight *runner.NextHeightLimits `json:",omitempty"`
	// ClockSkew moves the node's wall clock.
	ClockSkew time.Duration
	// TakeoverGuard sets the sign floor at start when the sign state is
	// empty and the head is above genesis.
	TakeoverGuard bool
	// WALSegmentBytes is the segment size of the write-ahead log (default
	// 256 KiB).
	WALSegmentBytes int64
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
	Cut      [][2]types.Address // cut both directions, for existing scenarios
	// DirectedCut cuts only the ordered from/to pair.
	DirectedCut [][2]types.Address
}

// Node actions of a NodeEvent.
const (
	ActionStop        = "stop"         // clean stop of the engine and the node
	ActionCrash       = "crash"        // kill: only what was synced survives
	ActionRestart     = "restart"      // start a stopped or crashed node
	ActionEngineStop  = "engine_stop"  // stop consensus while the application and transport remain live
	ActionEngineStart = "engine_start" // start consensus against the current application head
)

// NodeEvent controls a node or its consensus engine at a recorded time.
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
	// FailedImports makes the blocks a proposer builds at a height pass
	// proposal validation and fail import at every node after the
	// decision. A node records such a block as bad when its import fails,
	// so the bad-block rule releases the lock in the next round change.
	FailedImports []FailedImport
}

// FailedImport names a proposer and a height whose blocks fail import, and
// the time the import takes before it fails.
type FailedImport struct {
	Height   uint64
	Proposer types.Address
	Delay    time.Duration
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
	// RuleActivations contains chain-wide consensus rules, using exact decimal
	// activation heights. Missing rules are disabled. Node timing and profiles
	// never override these activations; nil preserves the original configuration.
	RuleActivations map[types.RuleName]string `json:",omitempty"`
	// AllowedFutureBlockTime preserves the chain's static future-block allowance.
	// Nil retains the original generated configuration; explicit zero is allowed.
	AllowedFutureBlockTime *uint64 `json:",omitempty"`
	// ProposerPolicy selects the recorded rotation rule; zero preserves the default.
	ProposerPolicy           uint64
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
	// DiskLoseState removes the sign state and the write-ahead log, as a
	// node that takes over a key without its sign record.
	DiskLoseState = "state_lost"
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
	// WallOrigin is the wall clock at simulated time zero, including its
	// fractional second. Zero snapshots Epoch when the run is initialized.
	// Each run retains its own origin across node and engine restarts.
	WallOrigin time.Time
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
	// MessageChanges select normal message deliveries, separate from adversaries.
	MessageChanges []MessageDeliveryChange `json:",omitempty"`
	Until          Stop
	// NoProgress disables the progress check.
	NoProgress bool
	// Log, when set, makes every node's runner log through a logcat level
	// table with these settings, into LogOut (nil: discarded). Log
	// settings must not change a run: events and journals are the same
	// whatever the levels (observe.md 7.1).
	Log    *logcat.Settings
	LogOut io.Writer
}

// DefaultNode is the default node: reference behaviour with the two
// restart-safety rules (consensus.RestartSafety of the core and the
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
	Kind   string // agreement, double_sign, progress, header, replay, lock_lost, refinalize, start, event_schema
	Node   types.Address
	Detail string
}

func (v Violation) String() string { return fmt.Sprintf("%s at %x: %s", v.Kind, v.Node[:4], v.Detail) }

// LightCheck records a partial light verdict alongside a successful state-bound check.
type LightCheck struct {
	Node              types.Address
	Number            string
	Hash              types.Hash
	Verdict           string
	Reason            string
	FullStateVerified bool
}

// Result is the outcome of a run.
type Result struct {
	LightChecks       []LightCheck                 `json:",omitempty"`
	MessageDeliveries []MessageDeliveryObservation `json:",omitempty"`
	Heads             []uint64                     // final head per node
	Chain             []*types.Block               // longest chain of the run, from genesis
	Rounds            map[uint64]uint64            // round of each decided height
	Violations        []Violation
	Evidence          int // EVIDENCE events written
	Crashes           int
	Replays           []runner.ReplayInfo
	Refinalize        int                                 // blocks finalized again by the start-up handshake
	Refusals          int                                 // signatures refused by the private validators of honest nodes
	LockChecks        int                                 // restored locks compared after a crash
	Damaged           int                                 // disk faults applied
	Journals          map[types.Address]map[string][]byte // journal files per node
	Events            map[string][]byte                   // event files by name
	SimTime           time.Duration
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
	res.MessageDeliveries, err = s.messageDeliveryResults()
	if err := writeOutput(out, res); err != nil {
		return res, err
	}
	return res, err
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
	messages *messageDeliveryControl
	sc       Scenario
	levels   *logcat.Levels // nil without Scenario.Log
	logBase  slog.Handler
	l        loop
	rng      *rand.Rand
	genesis  *types.Block
	nodes    []*node
	byAddr   map[types.Address]*node
	decided  map[uint64]types.Hash
	decBlock map[uint64]*types.Block
	rounds   map[uint64]uint64
	signed   map[signKey]types.Hash
	verified map[verificationKey]bool
	viol     []Violation
	crashes  int
	replays  []runner.ReplayInfo
	refinal  int
	locks    int
	evidence int
	refused  int
	damaged  int
	ctx      context.Context

	lightChecks []LightCheck
}

type verificationKey struct {
	Header                 types.Hash
	Config                 types.Hash
	FutureTimeAllowance    bool
	CheckEpochInfoPresence bool
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
	// The run may change these lists; the caller's scenario stays as it
	// was, so that it can be run again.
	sc.Validators = slices.Clone(sc.Validators)
	sc.Nodes = slices.Clone(sc.Nodes)
	sc.Params.MaxRequestTimeoutSeconds = cloneTimingValue(sc.Params.MaxRequestTimeoutSeconds)
	sc.Params.AllowedFutureBlockTime = cloneTimingValue(sc.Params.AllowedFutureBlockTime)
	sc.Params.RuleActivations = maps.Clone(sc.Params.RuleActivations)
	sc.Partitions = slices.Clone(sc.Partitions)
	sc.Schedule = slices.Clone(sc.Schedule)
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
	if sc.WallOrigin.IsZero() {
		sc.WallOrigin = Epoch
	}
	sc.WallOrigin = sc.WallOrigin.UTC().Round(0)
	if !validWallTime(sc.WallOrigin) || !validWallTime(sc.WallOrigin.Add(sc.Until.Duration)) {
		return nil, fmt.Errorf("%w: wall origin outside journal clock domain", ErrScenario)
	}
	cj, err := chainConfigJSON(sc.Params, sc.Validators[:sc.Genesis])
	if err != nil {
		return nil, err
	}
	cfg, err := types.ParseChainConfig(cj)
	if err != nil {
		return nil, err
	}
	g, err := genesisBlock(cfg, sc.WallOrigin)
	if err != nil {
		return nil, err
	}
	chainDomain, err := types.DomainForConfig(cfg, codec.BlockHash(g.Header))
	if err != nil {
		return nil, fmt.Errorf("%w: round-change chain domain: %v", ErrScenario, err)
	}
	s := &simulation{sc: sc, rng: rand.New(rand.NewPCG(uint64(sc.Seed), 0x5eed)), genesis: g,
		byAddr: map[types.Address]*node{}, decided: map[uint64]types.Hash{}, decBlock: map[uint64]*types.Block{},
		rounds: map[uint64]uint64{}, signed: map[signKey]types.Hash{}, verified: map[verificationKey]bool{}}
	s.decided[0] = codec.BlockHash(g.Header)
	if sc.Log != nil {
		out := sc.LogOut
		if out == nil {
			out = io.Discard
		}
		s.levels, s.logBase = logcat.NewLevels(), slog.NewTextHandler(out, &slog.HandlerOptions{Level: logcat.SlogLevelTrace})
		if _, err := s.levels.Apply(*sc.Log, "config", time.Time{}); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScenario, err)
		}
	}
	s.decBlock[0] = g
	for i := len(sc.Validators); i < len(sc.Nodes); i++ {
		if sc.Nodes[i].Timing != nil || sc.Nodes[i].NextHeight != nil {
			return nil, fmt.Errorf("%w: timing override for unknown node", ErrScenario)
		}
	}
	for i, v := range sc.Validators {
		spec := DefaultNode()
		if i < len(sc.Nodes) {
			spec = sc.Nodes[i]
		}
		spec.Timing = cloneTiming(spec.Timing)
		params, err := ResolveTiming(sc.Params, spec.Timing, sc.Until.Duration)
		if err != nil {
			return nil, err
		}
		nodeConfig, nodeConfigJSON := cfg, cj
		if spec.Timing != nil {
			candidate, err := chainConfigJSON(params, sc.Validators[:sc.Genesis])
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(candidate, cj) {
				nodeConfig, err = types.ParseChainConfig(candidate)
				if err != nil {
					return nil, err
				}
				nodeConfigJSON = candidate
			}
		}
		if err := consensus.CheckInitialRoundBudget(nodeConfig, spec.Options.Improvements); err != nil {
			return nil, fmt.Errorf("%w: node %d: %v", ErrScenario, i, err)
		}
		domain, err := types.DomainForConfig(nodeConfig, codec.BlockHash(g.Header))
		if err != nil || !chainDomain.Equal(domain) || spec.Options.RoundChangeDomain != nil && !spec.Options.RoundChangeDomain.Equal(domain) {
			return nil, fmt.Errorf("%w: node %d: round-change domain differs from the chain", ErrScenario, i)
		}
		if domain != nil && !spec.ReplayWAL {
			return nil, fmt.Errorf("%w: round-change domain requires WAL replay", ErrScenario)
		}
		spec.Options.RoundChangeDomain = domain.Copy()
		if !validWallTime(sc.WallOrigin.Add(spec.ClockSkew)) || !validWallTime(sc.WallOrigin.Add(spec.ClockSkew).Add(sc.Until.Duration)) {
			return nil, fmt.Errorf("%w: node wall clock outside journal domain", ErrScenario)
		}
		if err := validateApplicationSpec(spec, sc.Until.Duration); err != nil {
			return nil, err
		}
		processing, err := cloneProcessing(spec.Processing, sc.Until.Duration)
		if err != nil {
			return nil, err
		}
		spec.Processing = processing
		spec.WriteQueue, err = cloneWriteQueue(spec.WriteQueue, sc)
		if err != nil {
			return nil, err
		}
		spec.AcceptedCache, err = cloneAcceptedCache(spec.AcceptedCache, sc)
		if err != nil {
			return nil, err
		}
		spec.NextHeight, err = cloneNextHeight(spec.NextHeight, spec.ReplayWAL, processing)
		if err != nil {
			return nil, err
		}
		if spec.ValidatorHistory != nil && !spec.Options.Improvements.Has(consensus.DeferValidatorStart) {
			return nil, fmt.Errorf("%w: validator history requires defer_validator_start", ErrScenario)
		}
		if spec.Options.Improvements.Has(consensus.DeferValidatorStart) {
			if !spec.ReplayWAL {
				return nil, fmt.Errorf("%w: validator history requires WAL replay", ErrScenario)
			}
			limits := runner.DefaultValidatorHistoryLimits()
			if spec.ValidatorHistory != nil {
				limits = *spec.ValidatorHistory
			}
			if err := limits.Validate(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrScenario, err)
			}
			spec.ValidatorHistory = &limits
		}
		if spec.BuildQueuePolicy == BuildQueueSealing {
			effective := spec
			if len(effective.BuildDelay) == 0 {
				effective.BuildDelay = sc.App.BuildDelay
			}
			if len(effective.ImportDelay) == 0 {
				effective.ImportDelay = sc.App.ImportDelay
			}
			if err := validateApplicationSpec(effective, sc.Until.Duration); err != nil {
				return nil, err
			}
			for _, bad := range sc.App.BadProposals {
				if bad.Proposer == v.address {
					return nil, fmt.Errorf("%w: sealing profile requires empty proposals", ErrScenario)
				}
			}
			for _, bad := range sc.App.FailedImports {
				if bad.Proposer == v.address {
					return nil, fmt.Errorf("%w: sealing profile requires empty proposals", ErrScenario)
				}
			}
		}

		if spec.Sealing != nil {
			copy := *spec.Sealing
			copy.CallDelay = slices.Clone(copy.CallDelay)
			copy.PostDelay = slices.Clone(copy.PostDelay)
			spec.Sealing = &copy
		}
		if spec.StartAfter < 0 || spec.StartAfter >= sc.Until.Duration {
			return nil, fmt.Errorf("%w: invalid initial node start", ErrScenario)
		}
		for _, samples := range [][]time.Duration{spec.BuildDelay, spec.ImportDelay} {
			for _, d := range samples {
				if d < 0 || d > sc.Until.Duration {
					return nil, fmt.Errorf("%w: invalid node application delay", ErrScenario)
				}
			}
		}
		spec.BuildDelay = slices.Clone(spec.BuildDelay)
		spec.ImportDelay = slices.Clone(spec.ImportDelay)
		n := newNode(s, i, v, spec, nodeConfig, nodeConfigJSON)
		s.nodes = append(s.nodes, n)
		s.byAddr[v.address] = n
	}
	for _, scheduled := range sc.Schedule {
		n := s.byAddr[scheduled.Node]
		if n == nil || scheduled.At < n.spec.StartAfter || scheduled.At > sc.Until.Duration {
			return nil, fmt.Errorf("%w: schedule outside node lifetime", ErrScenario)
		}
		switch scheduled.Action {
		case ActionStop, ActionCrash, ActionRestart, ActionEngineStop, ActionEngineStart:
		default:
			return nil, fmt.Errorf("%w: unknown node action", ErrScenario)
		}
	}
	for _, partition := range sc.Partitions {
		if partition.From < 0 || partition.To <= partition.From {
			return nil, fmt.Errorf("%w: invalid partition interval", ErrScenario)
		}
		for _, pairs := range [][][2]types.Address{partition.Cut, partition.DirectedCut} {
			for _, pair := range pairs {
				if pair[0] == pair[1] || s.byAddr[pair[0]] == nil || s.byAddr[pair[1]] == nil {
					return nil, fmt.Errorf("%w: invalid partition endpoints", ErrScenario)
				}
			}
		}
	}
	if err := s.newMessageDeliveryControl(); err != nil {
		return nil, err
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
		if n.spec.StartAfter == 0 {
			n.start()
		} else {
			s.l.at(n.spec.StartAfter, func() {
				if !n.alive {
					n.start()
				}
			})
		}
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
				if !n.alive || n.down {
					n.start()
				}
			case ActionEngineStop, ActionEngineStart:
				n.requestEngineAction(ev.Action)
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
			s.l.c.AdvanceTo(s.sc.Until.Duration)
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
			if n.app.sealing != nil && n.app.sealing.pump() {
				progressed = true
			}
			if n.app.serial != nil && n.app.serial.pump() {
				progressed = true
			}
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
			s.violate("progress", n.v.address, "head %d below %d at %s", h, s.sc.Until.Height, s.l.c.Mono())
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

// eventSchema is the schema the event records of every node must match.
var eventSchema = sync.OnceValues(schema.Load)

// checkEvents reports the first record of each event file that does not
// match the event schema (observe/event/schema).
func (s *simulation) checkEvents() {
	sch, err := eventSchema()
	if err != nil {
		s.violate("event_schema", types.Address{}, "%v", err)
		return
	}
	for _, n := range s.nodes {
		for _, name := range sortedKeys(n.eventFiles) {
			for i, line := range bytes.SplitAfter(n.eventFiles[name].Bytes(), []byte("\n")) {
				if len(line) == 0 {
					continue
				}
				if err := sch.Validate(line); err != nil {
					s.violate("event_schema", n.v.address, "%s line %d: %v", name, i+1, err)
					break
				}
			}
		}
	}
}

func (s *simulation) result() *Result {
	s.checkEvents()
	res := &Result{Rounds: s.rounds, Violations: s.viol, Crashes: s.crashes, Replays: s.replays, Refinalize: s.refinal, Refusals: s.refused,
		LockChecks: s.locks, Damaged: s.damaged, Evidence: s.evidence, Journals: map[types.Address]map[string][]byte{}, Events: map[string][]byte{}, SimTime: s.l.c.Mono()}
	res.LightChecks = append([]LightCheck(nil), s.lightChecks...)
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

// logger returns the logger of module m for a node's runner, or nil
// without Scenario.Log.
func (s *simulation) logger(m logcat.Module) *slog.Logger {
	if s.levels == nil {
		return nil
	}
	return s.levels.Logger(m, s.logBase)
}

// moduleLogger returns the module loggers for a node's runner, or nil
// without Scenario.Log.
func (s *simulation) moduleLogger() func(logcat.Module) *slog.Logger {
	if s.levels == nil {
		return nil
	}
	return s.logger
}
