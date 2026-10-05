package logcat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
)

// ProfileFormat names the layout of a Profile.
const ProfileFormat = "wbft-log-profile/1"

// Profile is the inspector's implementation profile of wbft logs
// (observe.md 7, 5): how a log line maps to an event kind of the R-02
// vocabulary, for an inspector that receives logs without the event
// stream. A line is matched by its message, level and module; it carries
// the record's fields under the same keys as the event, plus Keys.
type Profile struct {
	Format string `json:"format"`
	// ID is "wbft@" and the first 12 hex digits of the SHA-256 of the
	// entries' JSON: it changes exactly when the mapping does, not with
	// every module version.
	ID      string         `json:"id"`
	Keys    []string       `json:"keys"`
	Entries []ProfileEntry `json:"entries"`
}

// ProfileEntry maps one log line to an event kind.
type ProfileEntry struct {
	Kind   string `json:"kind"`
	Module string `json:"module"`
	Level  string `json:"level"`
	Msg    string `json:"msg"`
}

// logConfigMsg is the message of the line that records the log settings
// (LOG_CONFIG), written by the node module.
const logConfigMsg = "log settings"

// LogConfigEntry returns the log line of the LOG_CONFIG record.
func LogConfigEntry() Entry { return Entry{Module: Node, Level: slog.LevelInfo, Msg: logConfigMsg} }

// commonKeys are the keys a catalog line carries besides the record's
// fields: the module, the view (h, r) and the step of the record.
var commonKeys = []string{"module", "h", "r", "step"}

// BuildProfile returns the profile of the event catalog and the log
// settings line.
func BuildProfile() Profile {
	var es []ProfileEntry
	add := func(kind string, e Entry) {
		es = append(es, ProfileEntry{Kind: kind, Module: e.Module.Name(), Level: levelName(e.Level), Msg: e.Msg})
	}
	for _, k := range EventKinds() {
		e, _ := EventEntry(k)
		add(k, e)
	}
	add("LOG_CONFIG", LogConfigEntry())
	sort.Slice(es, func(i, j int) bool { return es[i].Kind < es[j].Kind })
	b, err := json.Marshal(es)
	if err != nil {
		panic(err) // strings only
	}
	sum := sha256.Sum256(b)
	return Profile{Format: ProfileFormat, ID: "wbft@" + hex.EncodeToString(sum[:6]), Keys: commonKeys, Entries: es}
}

// ProfileID returns the ID of the profile (wbft_nodeInfo.logProfile,
// NODE_START.log_profile).
func ProfileID() string { return BuildProfile().ID }

// levelName is the name of a slog level as the profile writes it.
func levelName(l slog.Level) string {
	switch {
	case l <= SlogLevelTrace:
		return "trace"
	case l < slog.LevelInfo:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	}
	return "error"
}
