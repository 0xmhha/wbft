//go:build !wbft_faults

package faultpoint

// Enabled reports whether fault points call their handlers in this build.
const Enabled = false

// Hit does nothing in builds without the tag wbft_faults.
func Hit(Handler, string) {}
