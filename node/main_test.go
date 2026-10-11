package node

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/0xmhha/wbft/observe/event/schema"
)

var (
	eventSchema = sync.OnceValues(schema.Load)
	schemaMu    sync.Mutex
	schemaErrs  []string
)

// checkEvents checks the event records in p against the event schema and
// notes each mismatch for TestMain.
func checkEvents(p []byte) {
	s, err := eventSchema()
	for _, line := range bytes.SplitAfter(p, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if err == nil {
			err = s.Validate(line)
		}
		if err != nil {
			schemaMu.Lock()
			schemaErrs = append(schemaErrs, fmt.Sprintf("%v\n\t%s", err, bytes.TrimSpace(line)))
			schemaMu.Unlock()
			return
		}
	}
}

// TestMain fails the run when a test wrote an event record that does not
// match the event schema (observe/event/schema).
func TestMain(m *testing.M) {
	code := m.Run()
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if len(schemaErrs) > 0 {
		fmt.Fprintf(os.Stderr, "%d event record(s) do not match the event schema:\n", len(schemaErrs))
		for _, e := range schemaErrs[:min(len(schemaErrs), 10)] {
			fmt.Fprintln(os.Stderr, e)
		}
		code = 1
	}
	os.Exit(code)
}
