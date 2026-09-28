package event

import "github.com/0xmhha/wbft/types"

// Version is the format version written in the "v" field of every record.
const Version = 1

// Kind names an event. The spellings are shared with the conformance tools,
// which read event streams, frame dumps and vectors with the same checker.
type Kind string

// Event kinds.
const (
	NodeStart         Kind = "NODE_START"
	NodeStop          Kind = "NODE_STOP"
	EngineStart       Kind = "ENGINE_START"
	EngineStop        Kind = "ENGINE_STOP"
	RoundEnter        Kind = "ROUND_ENTER"
	StateChange       Kind = "STATE"
	TimerArm          Kind = "TIMER_ARM"
	TimerCancel       Kind = "TIMER_CANCEL"
	TimerFire         Kind = "TIMER_FIRE"
	PreprepareAccept  Kind = "PREPREPARE_ACCEPT"
	ProposalDeferred  Kind = "PROPOSAL_DEFERRED"
	Quorum            Kind = "QUORUM"
	Send              Kind = "SEND"
	Backlog           Kind = "BACKLOG"
	ExtraSeal         Kind = "EXTRA_SEAL"
	BuildRequest      Kind = "BUILD_REQUEST"
	ProposalSubmitted Kind = "PROPOSAL_SUBMITTED"
	FinalizeHandover  Kind = "FINALIZE_HANDOVER"
	NewHead           Kind = "NEW_HEAD"
	ImportFail        Kind = "IMPORT_FAIL"
	MsgOutcome        Kind = "MSG_OUTCOME"
	Evidence          Kind = "EVIDENCE"
	CommitResult      Kind = "COMMIT_RESULT"
	LogConfig         Kind = "LOG_CONFIG"
	Health            Kind = "HEALTH"
)

// OutcomeClass is the class of a received consensus message: what the node
// did with it, as seen from outside.
//
// Spec: WBFT-NET-044
type OutcomeClass string

// Outcome classes. Pending is used only by frame dump records whose outcome
// is decided asynchronously.
const (
	Accept     OutcomeClass = "ACCEPT"
	Ignore     OutcomeClass = "IGNORE"
	DropSilent OutcomeClass = "DROP_SILENT"
	Disconnect OutcomeClass = "DISCONNECT"
	Pending    OutcomeClass = "PENDING"
)

// SendCause is why a message was put on the wire.
type SendCause string

// Send causes.
const (
	CauseBroadcast SendCause = "broadcast" // own message to the validators
	CauseGossip    SendCause = "gossip"    // copy to an observer node
	CauseRelay     SendCause = "relay"     // relay of a received message
	CauseRetry     SendCause = "retry"     // ROUND-CHANGE rebuilt by the retry timer
	CauseReconnect SendCause = "reconnect" // last own ROUND-CHANGE to a reconnected peer
	CauseReplay    SendCause = "replay"    // own message re-sent after a restart
	CauseDirect    SendCause = "direct"    // reserved
)

// Round-change causes of ROUND_ENTER.cause.
const (
	CauseStart        = "start"
	CauseNewHead      = "new_head"
	CauseTimeout      = "timeout"
	CauseFPlusOne     = "f_plus_one"
	CauseFinalizeFail = "finalize_fail"
)

// NewHead paths of NEW_HEAD.path.
const (
	PathSealedLocally = "sealed_locally"
	PathImported      = "imported"
	PathSynced        = "synced"
)

// View is the "view" field: sequence and round as decimal strings.
type View struct {
	Seq   string `json:"seq"`
	Round string `json:"round"`
}

// ViewOf returns the event form of v.
func ViewOf(v types.View) *View {
	return &View{Seq: v.Sequence.String(), Round: v.Round.String()}
}

// Record is one event without the fields the writer stamps (node, run, seq,
// times). Fields holds the kind-specific fields; they are written at the top
// level of the JSON object in key order. Numbers that can exceed 64 bits
// (block numbers, rounds) are written as decimal strings by their producers.
type Record struct {
	Kind   Kind
	View   *View
	Imp    []string // identifiers of optional behaviours that decided this event
	Src    string   // "app" for records of application modules
	Fields map[string]any
}
