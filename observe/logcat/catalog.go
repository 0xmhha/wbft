package logcat

import (
	"log/slog"
	"sort"
)

// Entry is the log line of one event kind: its module, level and fixed
// message (observe.md 7: messages are constants, values are fields).
type Entry struct {
	Module Module
	Level  slog.Level
	Msg    string
}

// eventEntries is the catalog of the log lines the runner writes for its
// event records, by event kind. Round progress is consensus.round;
// messages, their outcomes and evidence are consensus.msg.
var eventEntries = map[string]Entry{
	"ENGINE_START":       {ConsensusRound, slog.LevelInfo, "consensus engine started"},
	"ENGINE_STOP":        {ConsensusRound, slog.LevelInfo, "consensus engine stopped"},
	"ROUND_ENTER":        {ConsensusRound, slog.LevelDebug, "round entered"},
	"STATE":              {ConsensusRound, slog.LevelDebug, "round state changed"},
	"TIMER_ARM":          {ConsensusRound, SlogLevelTrace, "timer armed"},
	"TIMER_CANCEL":       {ConsensusRound, SlogLevelTrace, "timer cancelled"},
	"TIMER_FIRE":         {ConsensusRound, slog.LevelDebug, "timer fired"},
	"PREPREPARE_ACCEPT":  {ConsensusRound, slog.LevelDebug, "proposal accepted"},
	"PROPOSAL_DEFERRED":  {ConsensusRound, slog.LevelDebug, "proposal deferred"},
	"QUORUM":             {ConsensusRound, slog.LevelDebug, "quorum reached"},
	"BUILD_REQUEST":      {ConsensusRound, SlogLevelTrace, "block build requested"},
	"PROPOSAL_SUBMITTED": {ConsensusRound, slog.LevelDebug, "proposal submitted"},
	"FINALIZE_HANDOVER":  {ConsensusRound, slog.LevelDebug, "decided block handed to the application"},
	"COMMIT_RESULT":      {ConsensusRound, slog.LevelInfo, "block finalized"},
	"NEW_HEAD":           {ConsensusRound, slog.LevelDebug, "new head"},
	"IMPORT_FAIL":        {ConsensusRound, slog.LevelWarn, "block import failed"},
	"SEND":               {ConsensusMsg, SlogLevelTrace, "message sent"},
	"MSG_OUTCOME":        {ConsensusMsg, SlogLevelTrace, "message handled"},
	"BACKLOG":            {ConsensusMsg, SlogLevelTrace, "message backlogged"},
	"EXTRA_SEAL":         {ConsensusMsg, SlogLevelTrace, "extra seal recorded"},
	"EVIDENCE":           {ConsensusMsg, slog.LevelWarn, "double signing evidence"},
	"HEALTH":             {ConsensusMsg, slog.LevelWarn, "receive path health"},
}

// EventEntry returns the log line of an event kind, and false for a kind
// the runner does not log.
func EventEntry(kind string) (Entry, bool) {
	e, ok := eventEntries[kind]
	return e, ok
}

// EventKinds returns the event kinds of the catalog in order.
func EventKinds() []string {
	out := make([]string, 0, len(eventEntries))
	for k := range eventEntries { //wbft:unordered sorted below
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
