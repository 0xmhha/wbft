package journal

import (
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
)

// NodeSourceEnds counts functional endings of verified recorded sources. A closed
// diagnostic writer or a zero pending count does not prove these endings. Even
// complete functional endings do not prove that both loops returned, Node.Stop
// returned, or DB/fs durability. The first writer-end or stream-removal path
// closes the functional session; the absent second callback is not invented.
type NodeSourceEnds struct {
	Status                       string `json:"status"`
	Engines                      uint64 `json:"engines,string"`
	EnginesWithoutStop           uint64 `json:"engines_without_stop,string"`
	ReceiveLedgers               uint64 `json:"receive_ledgers,string"`
	ReceiveWithoutClose          uint64 `json:"receive_without_close,string"`
	WriteLedgers                 uint64 `json:"write_ledgers,string"`
	WriteWithoutClose            uint64 `json:"write_without_close,string"`
	Sessions                     uint64 `json:"sessions,string"`
	SessionsWithoutOrigin        uint64 `json:"sessions_without_origin,string"`
	SessionsWithoutFunctionalEnd uint64 `json:"sessions_without_functional_end,string"`
	SessionsWithoutWriterEnd     uint64 `json:"sessions_without_writer_end,string"`
	SessionsWithoutRemoval       uint64 `json:"sessions_without_removal,string"`
	UnqualifiedSessions          uint64 `json:"unqualified_sessions,string"`
}

type nodeSourceLast struct {
	sequence uint64
	ended    bool
}
type nodeSessionEnds struct{ origin, writer, removed bool }

// Called only after the component inspectors accepted their explicit limits,
// independent state transitions and absence of relevant classified gaps. Cache
// sequence restores original mutex order; session callbacks are aggregated
// without inventing an order from callback delivery or timestamps.
func inspectNodeSourceEnds(records []Record) NodeSourceEnds {
	report := NodeSourceEnds{Status: "unavailable"}
	engines := map[appCoreKey]nodeSourceLast{}
	receives := map[writeCacheOwner]nodeSourceLast{}
	writes := map[writeCacheOwner]nodeSourceLast{}
	sessions := map[SessionRef]nodeSessionEnds{}
	writer := ""
	for _, record := range records {
		switch r := record.Body.(type) {
		case *SegmentRec:
			writer = r.Run
		case *CoreStepRec:
			key := appCoreKey{writer, r.EngineRun, 0}
			if previous := engines[key]; r.Step > previous.sequence {
				engines[key] = nodeSourceLast{r.Step, r.InputKind == inputlog.KindStop}
			}
		case *ReceiveCacheRec:
			key := writeCacheOwner{writer, r.Transition.Ledger}
			if previous := receives[key]; r.Transition.Sequence > previous.sequence {
				receives[key] = nodeSourceLast{r.Transition.Sequence, r.Transition.Action == transport.ReceiveLedgerClose}
			}
		case *WriteCacheRec:
			key := writeCacheOwner{writer, r.Transition.Ledger}
			if previous := writes[key]; r.Transition.Sequence > previous.sequence {
				writes[key] = nodeSourceLast{r.Transition.Sequence, r.Transition.Action == transport.WriteClose}
			}
		case *SessionRec:
			if r.Session == nil {
				report.UnqualifiedSessions++
				continue
			}
			ending := sessions[*r.Session]
			switch r.Event {
			case SessionObserved:
				ending.origin = ending.origin || writer == r.Session.Run
			case string(transport.SessionWriterEnded):
				ending.writer = true
			case string(transport.SessionRemoved):
				ending.removed = true
			}
			sessions[*r.Session] = ending
		}
	}
	for _, last := range engines { //wbft:unordered only commutative terminal counts are computed
		report.Engines++
		if !last.ended {
			report.EnginesWithoutStop++
		}
	}
	for _, last := range receives { //wbft:unordered only commutative terminal counts are computed
		report.ReceiveLedgers++
		if !last.ended {
			report.ReceiveWithoutClose++
		}
	}
	for _, last := range writes { //wbft:unordered only commutative terminal counts are computed
		report.WriteLedgers++
		if !last.ended {
			report.WriteWithoutClose++
		}
	}
	for _, ending := range sessions { //wbft:unordered only commutative terminal counts are computed
		report.Sessions++
		if !ending.origin {
			report.SessionsWithoutOrigin++
		}
		if !ending.writer && !ending.removed {
			report.SessionsWithoutFunctionalEnd++
		}
		if !ending.writer {
			report.SessionsWithoutWriterEnd++
		}
		if !ending.removed {
			report.SessionsWithoutRemoval++
		}
	}
	if report.Engines > 0 && report.ReceiveLedgers > 0 && report.WriteLedgers > 0 && report.Sessions > 0 && report.EnginesWithoutStop == 0 && report.ReceiveWithoutClose == 0 && report.WriteWithoutClose == 0 && report.SessionsWithoutOrigin == 0 && report.SessionsWithoutFunctionalEnd == 0 && report.UnqualifiedSessions == 0 {
		report.Status = "functional_sources_ended"
	}
	return report
}
