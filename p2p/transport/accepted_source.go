package transport

// AcceptedInputSource is a frozen diagnostic link to the original receive
// ticket and the core output selected by the runner. It grants no authority.
// Missing original qualifications must not be filled from a later recorder.
type AcceptedInputSource struct {
	LedgerRun              string
	Ledger, Scope, Request uint64
	Origin                 ReceiveOrigin
	Core                   ReceiveAcceptSource
}

func (t ReceiveTicket) AcceptedSource(core ReceiveAcceptSource) AcceptedInputSource {
	r := t.reservation
	if r == nil || r.owner == nil || core == (ReceiveAcceptSource{}) {
		return AcceptedInputSource{}
	}
	ledger := r.owner.ObservationSource()
	source := AcceptedInputSource{LedgerRun: ledger.WriterRun, Ledger: ledger.Ledger, Origin: r.origin, Core: core}
	if ledger.Ledger != 0 {
		source.Scope, source.Request = r.scope.ObservationID(), r.observation
	}
	return source
}
