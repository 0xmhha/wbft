//go:build wbft_faults

package faultpoint

// Enabled reports whether fault points call their handlers in this build.
const Enabled = true

// Hit calls h with name when h is not nil.
func Hit(h Handler, name string) {
	if h != nil {
		h(name)
	}
}
