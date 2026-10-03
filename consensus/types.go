package consensus

import (
	"fmt"
	"time"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/types"
)

// StateName is the consensus state of the current round.
//
// Spec: WBFT-SM-004
type StateName uint8

// Consensus states, in the order the reference compares them.
const (
	AcceptRequest StateName = iota
	Preprepared
	Prepared
	Committed
)

func (s StateName) String() string {
	switch s {
	case AcceptRequest:
		return "AcceptRequest"
	case Preprepared:
		return "Preprepared"
	case Prepared:
		return "Prepared"
	case Committed:
		return "Committed"
	}
	return "unknown"
}

// Class is the result of check_message.
//
// Spec: WBFT-SM-019
type Class uint8

// Classes. ClassNone marks a message discarded before classification
// (unknown code, undecodable payload, invalid signature).
const (
	ClassNone Class = iota
	Process
	Future
	Old
	Invalid
	TooFar
	ExtraSeal
)

func (c Class) String() string {
	switch c {
	case Process:
		return "PROCESS"
	case Future:
		return "FUTURE"
	case Old:
		return "OLD"
	case Invalid:
		return "INVALID"
	case TooFar:
		return "TOO_FAR"
	case ExtraSeal:
		return "EXTRA_SEAL"
	}
	return ""
}

// ParseClass returns the class with the given spelling.
func ParseClass(s string) (Class, bool) {
	for c := Process; c <= ExtraSeal; c++ {
		if c.String() == s {
			return c, true
		}
	}
	return ClassNone, false
}

// ParseStateName returns the state with the given spelling.
func ParseStateName(s string) (StateName, bool) {
	for st := AcceptRequest; st <= Committed; st++ {
		if st.String() == s {
			return st, true
		}
	}
	return 0, false
}

// TimerKind names one of the three timers of the core.
type TimerKind uint8

// Timer kinds.
const (
	RoundTimer  TimerKind = iota // round-change timer of the current view
	RetryTimer                   // ROUND-CHANGE retransmission timer
	FutureTimer                  // deferred PRE-PREPARE whose proposal is from the future
)

func (k TimerKind) String() string {
	switch k {
	case RoundTimer:
		return "round"
	case RetryTimer:
		return "retry"
	case FutureTimer:
		return "future"
	}
	return "unknown"
}

// AllTimers lists every timer kind.
var AllTimers = []TimerKind{RoundTimer, RetryTimer, FutureTimer}

// Protocol thresholds of check_message and the backlog.
//
// Spec: WBFT-SM-019, WBFT-SM-071
const (
	SequenceThreshold = 1
	RoundThreshold    = 10
	// MinBacklogLimit is the reference bound on backlogged messages per
	// source: 4 codes x (RoundThreshold + 1) rounds x (SequenceThreshold + 1)
	// sequences.
	MinBacklogLimit = 4 * (RoundThreshold + 1) * (SequenceThreshold + 1)
)

// Improvement names an optional local behaviour that differs from the
// reference. The set is carried in Options so that adding behaviours does
// not change the API.
type Improvement uint8

// Optional behaviours.
const (
	// OneRound0Proposal keeps the proposer from sending a second
	// PRE-PREPARE in a round-0 view once one was sent. The reference sends
	// a second, different one when another proposal request is handled
	// before the first PRE-PREPARE reached its own state. It is one of the
	// restart-safety rules: after a restart the proposer cannot tell from
	// preprepare_sent (0 either way) whether it already proposed.
	OneRound0Proposal Improvement = iota
	// BadBlockReleaseMark sets Broadcast.BadBlockReleased on a
	// ROUND-CHANGE whose prepared pair the bad-block rule released. The
	// messages are those of the reference; the mark lets the private
	// validator sign a ROUND-CHANGE without a prepared pair after the node
	// signed a COMMIT or a ROUND-CHANGE with a pair at that height. It is
	// one of the restart-safety rules: without it the sign rules of the
	// private validator refuse every such ROUND-CHANGE.
	BadBlockReleaseMark
)

// RestartSafety is the set of the restart-safety rules of the core. Nodes
// run with it; conformance vectors run with the empty set.
var RestartSafety = ImprovementSet(0).With(OneRound0Proposal).With(BadBlockReleaseMark)

// improvementNames are the names a node reports for its improvements
// (NODE_START, wbft_nodeInfo).
var improvementNames = [...]string{
	OneRound0Proposal:   "one_round0_proposal",
	BadBlockReleaseMark: "bad_block_release_mark",
}

// String returns the improvement's name.
func (i Improvement) String() string {
	if int(i) < len(improvementNames) {
		return improvementNames[i]
	}
	return fmt.Sprintf("improvement(%d)", int(i))
}

// Names returns the names of the improvements in the set, in their order.
func (s ImprovementSet) Names() []string {
	out := []string{}
	for i := range Improvement(len(improvementNames)) {
		if s.Has(i) {
			out = append(out, i.String())
		}
	}
	return out
}

// ImprovementSet is a set of optional behaviours, fixed when the core starts.
type ImprovementSet uint64

// Has reports whether i is in the set.
func (s ImprovementSet) Has(i Improvement) bool { return s&(1<<i) != 0 }

// With returns the set with i added.
func (s ImprovementSet) With(i Improvement) ImprovementSet { return s | 1<<i }

// Options configure a core. They are fixed for the life of the State.
type Options struct {
	// Config is the chain consensus configuration; timer durations and the
	// block period are read from ConfigAt of the view's sequence.
	Config *types.Config
	// Self is the node's address; the zero address for a node that never
	// signs.
	Self types.Address
	// Improvements selects optional behaviours. The zero value is the
	// reference behaviour.
	Improvements ImprovementSet
	// BacklogLimit bounds the backlogged messages per source. Zero means
	// MinBacklogLimit; a smaller positive value is raised to it.
	BacklogLimit int
}

// HeadInfo is the chain head as the core sees it: the head of the last
// processed NewHead, and its proposer (types.ProposerOf).
type HeadInfo struct {
	Header   *types.Header
	Proposer types.Address
}

// Env is the only way the core reads the outside world. Calls are
// synchronous; the runner records every answer so that a replay of the same
// inputs with the same answers produces the same outputs.
type Env interface {
	// Head returns the head of the last processed NewHead.
	Head() HeadInfo
	// ValidatorsAt returns the validator set that seals block number, whose
	// parent has hash parent (validators_at).
	ValidatorsAt(number types.Height, parent types.Hash) (*validator.Set, error)
	// ValidateProposal is validate_proposal. A proposal from the future
	// fails with an error that wraps header.ErrFutureBlock and returns the
	// time to wait.
	ValidateProposal(b *types.Block) (future time.Duration, err error)
	// IsBadBlock reports whether the application marked the block as bad.
	IsBadBlock(h types.Hash) bool
	// CommitHeader writes the seals and the round into the header of b
	// (header.CommitHeader) and returns the sealed block; its failure is the
	// failure of finalize.
	CommitHeader(b *types.Block, round types.Round, vs *validator.Set, prepared, committed []types.SealEntry) (*types.Block, error)
}
