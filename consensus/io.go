package consensus

import (
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
	"github.com/0xmhha/wbft/validator"
)

// Input is one event for the core. Each Step processes exactly one input.
type Input interface{ isInput() }

// Start starts the core: a new core state at the view after the head.
//
// Spec: WBFT-SM-004, WBFT-SM-008
type Start struct{}

// Stop stops the core: all timers are cancelled and the state is discarded.
//
// Spec: WBFT-SM-009
type Stop struct{}

// NewHead reports that the application head changed. The core reads the head
// through Env.Head; Header is carried for records only.
//
// Spec: WBFT-SM-010
type NewHead struct{ Header *types.Header }

// Request hands over a proposal built by the block builder, or replays a
// stored request.
//
// Spec: WBFT-SM-031
type Request struct{ Block *types.Block }

// Message is a consensus message received from a peer, or the self-delivery
// of a message the node broadcast (Peer is then the node itself).
//
// Spec: WBFT-SM-014, WBFT-SM-015
type Message struct {
	Code     codec.Code
	Payload  []byte
	Peer     types.Address
	RecvMono time.Duration
}

// Replay is the replay of a backlogged message or the re-injection of a
// deferred PRE-PREPARE. Its signatures are not verified again.
//
// Spec: WBFT-SM-074
type Replay struct{ Msg *Verified }

// Timeout is the expiry of a timer armed with ArmTimer. Gen is the
// generation of that ArmTimer. Round is the round a retry timer remembers.
type Timeout struct {
	Kind  TimerKind
	View  types.View
	Round types.Round
	Gen   uint64
}

// CommitResult reports the result of importing a committed block. The
// reference does not learn it; the core records nothing.
type CommitResult struct {
	Hash types.Hash
	Err  error
}

// BroadcastFailed reports that a Broadcast output could not be signed or
// sent.
type BroadcastFailed struct {
	Code codec.Code
	View types.View
}

// PeerConnected reports that a validator peer (re)connected.
type PeerConnected struct{ Addr types.Address }

func (Start) isInput()           {}
func (Stop) isInput()            {}
func (NewHead) isInput()         {}
func (Request) isInput()         {}
func (Message) isInput()         {}
func (Replay) isInput()          {}
func (Timeout) isInput()         {}
func (CommitResult) isInput()    {}
func (BroadcastFailed) isInput() {}
func (PeerConnected) isInput()   {}

// Output is one action the runner executes, in the order given.
type Output interface{ isOutput() }

// Broadcast is an unsigned message of the node. The runner signs it (and, for
// PREPARE and COMMIT, fills Msg.Seal with the BLS signature of SealData),
// sends it to Validators and delivers it to the core as a Message.
//
// Spec: WBFT-SM-014
type Broadcast struct {
	Msg        *codec.Message
	SealData   []byte
	Validators *validator.Set
}

// Relay sends a processed message to Validators: the received bytes, or the
// re-encoding of a replayed message.
//
// Spec: WBFT-SM-011, WBFT-SM-012
type Relay struct {
	Code       codec.Code
	Payload    []byte
	Validators *validator.Set
}

// Schedule queues an input for later processing by the same core: a backlog
// replay, a deferred PRE-PREPARE or a stored request. It must not be
// processed within the Step that returned it.
//
// Spec: WBFT-SM-002
type Schedule struct{ In Input }

// ArmTimer arms a timer of Kind for Duration; any timer of the same kind that
// is still armed is cancelled. The expiry comes back as Timeout with the same
// Gen. View is the view the timer belongs to (for a future timer the view of
// the deferred PRE-PREPARE); Round is the round a retry timer remembers;
// Digest is the proposal of a future timer.
type ArmTimer struct {
	Kind     TimerKind
	View     types.View
	Round    types.Round
	Duration time.Duration
	Gen      uint64
	Digest   types.Hash
}

// CancelTimers cancels the armed timers of the given kinds.
type CancelTimers struct{ Kinds []TimerKind }

// RequestBuild tells the block builder that a round started (ready_to_build).
// Round is the requested round of start_new_round. The builder waits
// BuildWait(HeadTime, BlockPeriod, Round, now) before it builds block Height.
//
// Spec: WBFT-SM-029
type RequestBuild struct {
	Height      types.Height
	Round       types.Round
	HeadTime    uint64
	BlockPeriod uint64
}

// Commit hands a decided block, with the seals written into its header, to
// the application.
//
// Spec: WBFT-SM-047
type Commit struct {
	Block *types.Block
	Round types.Round
}

// Outcome reports how the core disposed of one message: its check_message
// class, the row of the outcome table and whether it was relayed. Via is
// "direct" for a Message and "backlog" for a Replay.
type Outcome struct {
	Code     codec.Code
	Source   types.Address
	View     types.View
	Check    Class
	Row      int
	Relayed  bool
	Via      string
	Peer     types.Address
	DedupKey types.Hash
}

// Event is an observation record for the event stream.
type Event struct{ Record event.Record }

func (Broadcast) isOutput()    {}
func (Relay) isOutput()        {}
func (Schedule) isOutput()     {}
func (ArmTimer) isOutput()     {}
func (CancelTimers) isOutput() {}
func (RequestBuild) isOutput() {}
func (Commit) isOutput()       {}
func (Outcome) isOutput()      {}
func (Event) isOutput()        {}

// Class returns the A-07 outcome class of a message that reached the core:
// ACCEPT when it was relayed, IGNORE otherwise.
func (o Outcome) Class() event.OutcomeClass {
	if o.Relayed {
		return event.Accept
	}
	return event.Ignore
}

// Record returns the MSG_OUTCOME event of o.
func (o Outcome) Record() event.Record {
	f := map[string]any{
		"code":      uint64(o.Code),
		"check":     o.Check.String(),
		"outcome":   o.Class(),
		"row":       o.Row,
		"via":       o.Via,
		"peer":      hexAddr(o.Peer),
		"dedup_key": hexHash(o.DedupKey),
	}
	if o.Check == ClassNone {
		f["check"] = nil
	}
	if o.Source != (types.Address{}) {
		f["source"] = hexAddr(o.Source)
	}
	return event.Record{Kind: event.MsgOutcome, View: event.ViewOf(o.View), Fields: f}
}
