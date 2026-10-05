package sim

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/observe/logcat"
)

// TestLogLevelsDoNotChangeRun runs scenarios twice with the same seed, once
// with every log module at trace and once at off: the event files are the
// same bytes, and the journals have the same records and step out_digests
// (observe.md 7.1: log settings act on log lines only).
func TestLogLevelsDoNotChangeRun(t *testing.T) {
	keys := testValidators(t, 7)
	byName := map[string]Template{}
	for _, tpl := range Bundle() {
		byName[tpl.Name] = tpl
	}
	lines := 0
	for _, name := range []string{"restarts", "inbound_overflow", "double_signer"} {
		tpl := byName[name]
		run := func(lv logcat.Level, logOut *bytes.Buffer) (events map[string][]byte, steps []string, records int) {
			t.Helper()
			sc := tpl.Make(7, keys[:tpl.Needs])
			sc.Log, sc.LogOut = &logcat.Settings{Base: lv}, logOut
			dir := t.TempDir()
			res, err := Run(context.Background(), sc, Output{EventsDir: filepath.Join(dir, "events"), JournalDir: filepath.Join(dir, "journal")})
			if err != nil || len(res.Violations) != 0 {
				t.Fatalf("%s: %v %v", name, err, res.Violations)
			}
			events = map[string][]byte{}
			es, err := os.ReadDir(filepath.Join(dir, "events"))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range es {
				b, err := os.ReadFile(filepath.Join(dir, "events", e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				events[e.Name()] = b
			}
			nodes, _, err := ReadJournalDir(filepath.Join(dir, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			for _, nd := range nodes {
				recs, err := journal.ReadAll(nil, nd)
				if err != nil {
					t.Fatal(err)
				}
				records += len(recs)
				for _, r := range recs {
					if s, ok := r.Body.(*journal.StepRec); ok {
						steps = append(steps, filepath.Base(nd)+" "+s.OutDigest.String())
					}
				}
			}
			return events, steps, records
		}
		var traceOut, offOut bytes.Buffer
		evTrace, stepsTrace, nTrace := run(logcat.LevelTrace, &traceOut)
		evOff, stepsOff, nOff := run(logcat.LevelOff, &offOut)
		if len(evTrace) == 0 || len(evTrace) != len(evOff) {
			t.Fatalf("%s: %d event files at trace, %d at off", name, len(evTrace), len(evOff))
		}
		for f, b := range evTrace {
			if !bytes.Equal(b, evOff[f]) {
				t.Fatalf("%s: event file %s differs between trace and off", name, f)
			}
		}
		if nTrace != nOff || len(stepsTrace) == 0 || strings.Join(stepsTrace, "\n") != strings.Join(stepsOff, "\n") {
			t.Fatalf("%s: journal records %d and %d, steps %d and %d", name, nTrace, nOff, len(stepsTrace), len(stepsOff))
		}
		if offOut.Len() != 0 {
			t.Fatalf("%s: log lines with every module off:\n%s", name, offOut.String())
		}
		lines += strings.Count(traceOut.String(), "\n")
	}
	// The trace runs must have logged, or the comparison shows nothing.
	if lines == 0 {
		t.Fatal("no log line was written at trace")
	}
	t.Logf("log lines written at trace: %d", lines)
}
