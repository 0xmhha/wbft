// Command wbft-logprofile writes the inspector's log profile of wbft
// (observe.md 7, 5): which log line is which event kind, for an inspector
// that receives a node's logs without its event stream. The profile's ID
// is what wbft_nodeInfo.logProfile and NODE_START.log_profile report.
//
// Usage:
//
//	wbft-logprofile > wbft-profile.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/0xmhha/wbft/observe/logcat"
)

func main() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(logcat.BuildProfile()); err != nil {
		fmt.Fprintln(os.Stderr, "wbft-logprofile:", err)
		os.Exit(1)
	}
}
