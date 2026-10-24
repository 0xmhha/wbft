package journal

import (
	"testing"

	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/p2p/transport"
)

func TestNodeSourceEndDiagnosticCounts(t *testing.T) {
	session := &SessionRef{Run: "closed-normal", Ordinal: 1}
	original := []Record{
		{Body: &SegmentRec{Identity: Identity{Run: session.Run}}},
		{Body: &CoreStepRec{EngineRun: 1, Step: 2, InputKind: inputlog.KindStop}},
		{Body: &ReceiveCacheRec{Transition: transport.ReceiveTransition{Ledger: 1, Sequence: 3, Action: transport.ReceiveLedgerClose}}},
		{Body: &WriteCacheRec{Transition: transport.WriteTransition{Ledger: 1, Sequence: 5, Action: transport.WriteClose}}},
		{Body: &SessionRec{Session: session, Event: SessionObserved}},
		{Body: &SessionRec{Session: session, Event: string(transport.SessionRemoved)}},
	}
	for _, name := range []string{"original", "writer_only", "without_origin", "without_end", "without_stop", "lower_sequence_after_close"} {
		t.Run(name, func(t *testing.T) {
			rows := append([]Record(nil), original...)
			switch name {
			case "writer_only":
				rows[5].Body = &SessionRec{Session: session, Event: string(transport.SessionWriterEnded)}
			case "without_origin":
				rows = append(rows[:4], rows[5:]...)
			case "without_end":
				rows = rows[:5]
			case "without_stop":
				rows[1].Body = &CoreStepRec{EngineRun: 1, Step: 2, InputKind: inputlog.KindMessage}
			case "lower_sequence_after_close":
				rows = append(rows, Record{Body: &WriteCacheRec{Transition: transport.WriteTransition{Ledger: 1, Sequence: 4, Action: transport.WritePrepare}}})
			}
			report := inspectNodeSourceEnds(rows)
			want := "functional_sources_ended"
			if name == "without_origin" || name == "without_end" || name == "without_stop" {
				want = "unavailable"
			}
			if report.Status != want {
				t.Fatal(report, want)
			}
			if name == "writer_only" && (report.SessionsWithoutRemoval != 1 || report.SessionsWithoutWriterEnd != 0) {
				t.Fatal(report)
			}
			if name == "original" && (report.SessionsWithoutWriterEnd != 1 || report.SessionsWithoutFunctionalEnd != 0) {
				t.Fatal(report)
			}
		})
	}
	if inspectNodeSourceEnds(original).Status != "functional_sources_ended" {
		t.Fatal("inspection modified original diagnostic metadata")
	}
}
