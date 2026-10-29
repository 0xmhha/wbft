package journal

import (
	"errors"

	"github.com/0xmhha/wbft/consensus/privval"
)

// SignerOriginRun supplies original source records from one earlier writer,
// one WAL reader lifetime and one signer lifetime. Inputs must remain immutable
// for the duration of an inspection.
type SignerOriginRun struct{ Records []Record }

// SignerOriginLink is an explicit logical handoff witness. Reader identifiers
// alone do not identify an earlier writer or prove filesystem continuity.
type SignerOriginLink struct {
	PreviousRead, CurrentRead     WALReadRef
	PreviousSigner, CurrentSigner privval.SourceRef
}

// SignerOriginSources supports one ordered predecessor chain, oldest first.
// Links[i] joins Prior[i] to Prior[i+1], or to the current records at the end.
// It contains source evidence, never a caller-supplied validation certificate.
type SignerOriginSources struct {
	Prior []SignerOriginRun
	Links []SignerOriginLink
}

// SignerOriginLimits bound the complete origin inspection. Work is a logical
// inspection-cost model, not a CPU, allocation or physical-runtime guarantee.
// Independent node and application inspectors retain their existing sublimits;
// their additional inspection passes also consume this origin work allowance.
type SignerOriginLimits struct {
	Core                                CoreSourceLimits
	Signer                              privval.SourceLimits
	Writers, Links, Frames, Bytes, Work uint64
}

// SignerOriginUsage counts charged inputs and inspection work, including
// repeated passes. Conservative reservations are not refunded.
type SignerOriginUsage struct {
	Core                                CoreSourceLimits
	Signer                              privval.SourceLimits
	Writers, Links, Frames, Bytes, Work uint64
}

// RestoredSignerOriginCheck distinguishes current-only evidence from inherited
// own-message bindings. Inherited bindings never increase Current.Calls.
type RestoredSignerOriginCheck struct {
	Status, Reason, Scope, PhysicalStatus  string
	OriginStatus, OriginScope              string
	Current                                RestoreSignerCheck
	CurrentInspected                       bool
	PriorRuns, Links, InheritedOwnBindings uint64
	Usage                                  SignerOriginUsage
}

// NodeExecutionOriginCheck requires independent node, signing-origin and
// application checks. Legacy retains the exact old result on an empty request;
// an old partial result is never relabeled as a successful origin inspection.
type NodeExecutionOriginCheck struct {
	Status, Reason, Scope                             string
	PhysicalStatus, ScheduleStatus, TerminationStatus string
	OriginStatus                                      string
	Legacy                                            NodeExecutionCheck
	Node                                              NodeSourceCheck
	Signer                                            RestoredSignerOriginCheck
	Application                                       ApplicationCheck
}

var ErrSignerOrigin = errors.New("journal: inconsistent signing origin")
