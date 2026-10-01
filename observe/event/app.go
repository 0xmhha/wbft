package event

// AppEmitter puts the records of an application module into the node's
// event stream. The node stamps them like its own records (node, run, seq,
// times) and marks them with src "app". The module owns its kinds and their
// fields; the stream does not check the fields. A kind the node writes
// itself is refused, so a module cannot imitate a consensus event.
type AppEmitter interface {
	// Emit writes one record. It never fails: a refused or unwritable
	// record is dropped and logged by the node.
	Emit(kind Kind, fields map[string]any)
}

// nodeKinds are the kinds the node writes itself.
var nodeKinds = map[Kind]bool{
	NodeStart: true, NodeStop: true, EngineStart: true, EngineStop: true, RoundEnter: true,
	StateChange: true, TimerArm: true, TimerCancel: true, TimerFire: true, PreprepareAccept: true,
	ProposalDeferred: true, Quorum: true, Send: true, Backlog: true, ExtraSeal: true,
	BuildRequest: true, ProposalSubmitted: true, FinalizeHandover: true, NewHead: true,
	ImportFail: true, MsgOutcome: true, Evidence: true, CommitResult: true, LogConfig: true,
	Health: true,
}

// IsNodeKind reports whether the node writes records of kind k itself; an
// application module may not use it.
func IsNodeKind(k Kind) bool { return nodeKinds[k] }

// AppSrc is the src of the records an application module emits.
const AppSrc = "app"
