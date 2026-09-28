// Command wbft-replay replays a recorded message journal through the
// consensus core and reports, step by step, whether the replayed outputs
// match the recorded ones. It wraps package conformance/stepdriver behind the
// line-based JSON protocol wbft-replay/1 on standard input and output, so
// that analysis tools can run the core that matches the recording.
//
// Status (milestone W0): not implemented; the command exits with status 2.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "wbft-replay: not implemented yet")
	os.Exit(2)
}
