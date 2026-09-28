// Command wbft-vector-adapter runs the wbft consensus layer under a
// conformance vector runner. It speaks the adapter protocol wbft-vector/1
// (specification A-11 §3.4): the runner starts it as a child process and
// exchanges one JSON object per line over standard input and output.
//
// Usage:
//
//	wbft-vector-adapter            # conformance run; reads stdin, writes stdout
//	wbft-vector-adapter -version   # print version information and exit
//
// Standard output carries protocol messages only; diagnostics go to standard
// error. The adapter never reads vector files: everything it needs arrives in
// the case message.
//
// The adapter answers the handlers of the consensus layer; cases of other
// handlers, and network cases whose verdict belongs to a transport adapter,
// are answered "unsupported".
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

// Build metadata; release builds set these with -ldflags "-X main.version=...".
var (
	version = "0.0.0-dev"
	commit  = ""
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "wbft-vector-adapter: unexpected arguments %q\n", flag.Args())
		os.Exit(exitUsage)
	}
	info := implInfo()
	if *showVersion {
		fmt.Fprintf(os.Stderr, "%s %s (commit %s, %s build)\n", info.Name, info.Version, info.Commit, info.Build)
		os.Exit(exitOK)
	}
	os.Exit(serve(os.Stdin, os.Stdout, os.Stderr, info))
}

// implInfo returns the "impl" object of the adapter's hello.
func implInfo() Impl {
	c := commit
	if c == "" {
		c = vcsRevision()
	}
	return Impl{
		Name:    "wbft",
		Version: version,
		Commit:  c,
		Lang:    "go",
		// wbft is built with cgo only (blst and the cgo secp256k1 of
		// go-ethereum); the field is informative (WBFT-VEC-038).
		Build: "cgo",
	}
}

// vcsRevision reads the VCS revision stamped by the go command, if any.
func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}
