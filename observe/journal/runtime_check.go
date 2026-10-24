package journal

import (
	"errors"
	"fmt"
	"slices"

	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/types"
)

type RuntimeLimits struct{ Records, Operations, Sessions, Bytes uint64 }

type RuntimeCheck struct {
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope"`
	PhysicalStatus string `json:"physical_status"`
	Operations     uint64 `json:"operations,string"`
	Sessions       uint64 `json:"sessions,string"`
	ReturnedLoops  uint64 `json:"returned_loops,string"`
	ReturnedCalls  uint64 `json:"returned_calls,string"`
	CoreStops      uint64 `json:"core_stops,string"`
	RetainedCalls  uint64 `json:"retained_calls,string"`
}

var ErrRuntimeSource = errors.New("journal: inconsistent runtime source")

type runtimeOwner struct {
	run       string
	session   uint64
	component RuntimeComponent
}
type runtimeOriginalSession struct {
	peer  types.Address
	index int
	mono  uint64
}
type runtimeInterval struct{ entry, returned *RuntimeRec }

// CheckRuntimeSources checks original return boundaries separately from first
// functional session endings. It accepts finite observed sources conditionally,
// not authenticated process history, remote delivery or physical durability.
func CheckRuntimeSources(records []Record, limits RuntimeLimits) (RuntimeCheck, error) {
	report := RuntimeCheck{Status: "unavailable", Scope: "original_loop_and_shutdown_return_boundaries", PhysicalStatus: "unavailable"}
	unavailable := func(reason string) (RuntimeCheck, error) {
		report.Status, report.Reason = "unavailable", reason
		return report, nil
	}
	bad := func(reason string) (RuntimeCheck, error) {
		report.Status, report.Reason = "inconsistent", reason
		return report, fmt.Errorf("%w: %s", ErrRuntimeSource, reason)
	}
	if limits.Records == 0 || limits.Operations == 0 || limits.Sessions == 0 || limits.Bytes == 0 {
		return unavailable("inspection_limits_required")
	}
	if uint64(len(records)) > limits.Records {
		return unavailable("record_limit")
	}
	groups := map[string][]*RuntimeRec{}
	profiles := map[string]string{}
	origins := map[SessionRef]runtimeOriginalSession{}
	indexes := map[*RuntimeRec]int{}
	coreStops := map[string][]*CoreStepRec{}
	run := ""
	var span uint64
	for index, row := range records {
		switch r := row.Body.(type) {
		case *SegmentRec:
			run = r.Run
			if previous, found := profiles[run]; found && previous != r.Mode {
				return bad("runtime_profile_changed")
			}
			profiles[run] = r.Mode
		case *GapRec:
			if r.Dropped > 0 && len(r.ByKind) == 0 {
				return unavailable("unclassified_gap")
			}
			for _, k := range r.ByKind {
				if k.Count > 0 && (k.Kind == 0 || k.Kind == uint64(KindRuntime) || k.Kind == uint64(KindSession) || k.Kind == uint64(KindCoreStep)) {
					return unavailable("runtime_source_gap")
				}
			}
		case *SessionRec:
			if r.Session == nil || r.Event != SessionObserved || r.Session.Run != run {
				continue
			}
			if original, found := origins[*r.Session]; found {
				if original.peer != r.Peer {
					return bad("session_origin_peer_changed")
				}
				// Registering an already observed object again does not start a new
				// lifetime. Preserve its earliest original observation.
				continue
			}
			if uint64(len(origins)) >= limits.Sessions {
				return unavailable("session_limit")
			}
			origins[*r.Session] = runtimeOriginalSession{r.Peer, index, uint64(r.Mono)}
		case *CoreStepRec:
			if r.InputKind == inputlog.KindStop {
				coreStops[run] = append(coreStops[run], r)
			}
		case *RuntimeRec:
			if report.Operations >= limits.Operations {
				return unavailable("operation_limit")
			}
			if !validRuntimeRec(r) {
				return bad("invalid_runtime_source")
			}
			if r.Unavailable != "" {
				return unavailable("runtime_" + r.Unavailable)
			}
			if run == "" || run != r.Namespace {
				return bad("runtime_writer_changed")
			}
			n := uint64(size(row))
			if n > limits.Bytes-span {
				return unavailable("byte_limit")
			}
			span += n
			report.Operations++
			groups[run] = append(groups[run], r)
			indexes[r] = index
		}
	}
	if report.Operations == 0 {
		return unavailable("no_runtime_sources")
	}
	names := make([]string, 0, len(groups))
	for name := range groups { //wbft:unordered sorted before checking
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		rows := groups[name]
		slices.SortFunc(rows, func(a, b *RuntimeRec) int {
			if a.Sequence < b.Sequence {
				return -1
			}
			if a.Sequence > b.Sequence {
				return 1
			}
			return 0
		})
		pending := map[uint64]*RuntimeRec{}
		loops := map[runtimeOwner]runtimeInterval{}
		calls := map[RuntimeComponent]runtimeInterval{}
		var previous, mono uint64
		for _, r := range rows {
			if r.Sequence == previous {
				return bad("runtime_sequence_repeated")
			}
			if r.Sequence != previous+1 {
				return unavailable("runtime_sequence_gap")
			}
			if r.Mono < mono {
				return bad("runtime_clock_changed")
			}
			previous, mono = r.Sequence, r.Mono
			if r.Phase == "enter" {
				if runtimeLoop(r.Component) {
					origin, found := origins[SessionRef{Run: r.SessionRun, Ordinal: r.Session}]
					if !found {
						return unavailable("runtime_original_session_missing")
					}
					if origin.peer != r.Peer || indexes[r] <= origin.index || r.Mono < origin.mono {
						return bad("runtime_session_owner_or_entry_changed")
					}
					key := runtimeOwner{r.SessionRun, r.Session, r.Component}
					if _, found := loops[key]; found {
						return bad("runtime_loop_repeated")
					}
					loops[key] = runtimeInterval{entry: r}
				} else {
					if _, found := calls[r.Component]; found {
						return unavailable("multiple_shutdown_calls_not_supported")
					}
					calls[r.Component] = runtimeInterval{entry: r}
				}
				pending[r.Request] = r
				continue
			}
			entry, found := pending[r.Request]
			if !found {
				return unavailable("runtime_original_entry_missing")
			}
			if entry.Namespace != r.Namespace || entry.Component != r.Component || entry.SessionRun != r.SessionRun || entry.Session != r.Session || entry.Peer != r.Peer || entry.Mono > r.Mono || indexes[entry] >= indexes[r] {
				return bad("runtime_return_owner_or_order_changed")
			}
			if runtimeLoop(r.Component) {
				key := runtimeOwner{r.SessionRun, r.Session, r.Component}
				interval := loops[key]
				interval.returned = r
				loops[key] = interval
				report.ReturnedLoops++
			} else {
				if r.Result != "ok" {
					return unavailable("shutdown_call_failed")
				}
				interval := calls[r.Component]
				interval.returned = r
				calls[r.Component] = interval
				report.ReturnedCalls++
			}
			delete(pending, r.Request)
		}
		report.RetainedCalls += uint64(len(pending))
		if len(pending) != 0 {
			return unavailable("unfinished_runtime_calls")
		}
		required := []RuntimeComponent{RuntimeNodeStop, RuntimeBaseStop, RuntimeAppStop}
		switch profiles[name] {
		case "standalone":
			required = append(required, RuntimeHostStop, RuntimeDBClose)
		case "embedded":
			required = append(required, RuntimeStackClose, RuntimeWritersJoin)
		default:
			return unavailable("runtime_profile_unavailable")
		}
		for _, component := range required {
			if calls[component].returned == nil {
				return unavailable("shutdown_return_missing")
			}
		}
		app, node, base := calls[RuntimeAppStop], calls[RuntimeNodeStop], calls[RuntimeBaseStop]
		var transportReturn *RuntimeRec
		switch profiles[name] {
		case "standalone":
			host, db := calls[RuntimeHostStop], calls[RuntimeDBClose]
			if base.entry.Mono < app.entry.Mono || host.entry.Mono < app.entry.Mono || db.entry.Mono < app.entry.Mono || node.returned.Mono > db.entry.Mono || base.returned.Mono > db.entry.Mono || host.returned.Mono > app.returned.Mono || db.returned.Mono > app.returned.Mono || node.returned.Mono > app.returned.Mono {
				return bad("shutdown_return_order_changed")
			}
			transportReturn = host.returned
		case "embedded":
			stack, joined := calls[RuntimeStackClose], calls[RuntimeWritersJoin]
			if base.entry.Mono < app.entry.Mono || stack.entry.Mono < app.entry.Mono || node.returned.Mono > stack.entry.Mono || base.returned.Mono > stack.entry.Mono || stack.returned.Mono > joined.entry.Mono || joined.returned.Mono > app.returned.Mono {
				return bad("shutdown_return_order_changed")
			}
			transportReturn = joined.returned
		}

		if len(coreStops[name]) == 0 {
			return unavailable("original_core_stop_missing")
		}
		for _, stop := range coreStops[name] {
			if uint64(stop.Entry.Mono) < node.entry.Mono || uint64(stop.Observed.Mono) > node.returned.Mono {
				return bad("core_stop_outside_original_call")
			}
			report.CoreStops++
		}
		for ref, origin := range origins { //wbft:unordered all sessions must satisfy the same boundaries
			if ref.Run != name {
				continue
			}
			report.Sessions++
			reader := loops[runtimeOwner{ref.Run, ref.Ordinal, RuntimeReader}]
			writer := loops[runtimeOwner{ref.Run, ref.Ordinal, RuntimeWriter}]
			protocol := loops[runtimeOwner{ref.Run, ref.Ordinal, RuntimeProtocol}]
			if reader.returned == nil || writer.returned == nil || protocol.returned == nil {
				return unavailable("session_loop_return_missing")
			}
			if reader.entry.Peer != origin.peer || writer.entry.Peer != origin.peer || protocol.entry.Peer != origin.peer || reader.entry.Mono < protocol.entry.Mono || reader.returned.Mono > protocol.returned.Mono || writer.entry.Mono < protocol.entry.Mono || reader.returned.Mono > transportReturn.Mono || writer.returned.Mono > transportReturn.Mono || protocol.returned.Mono > transportReturn.Mono {
				return bad("session_loop_return_boundary_changed")
			}
		}
	}
	if report.Sessions == 0 {
		return unavailable("no_original_sessions")
	}
	report.Status, report.Reason = "consistent", ""
	return report, nil
}
