package main

import (
	"os"

	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

type bundleResult struct {
	Out      string                  `json:"out"`
	Format   string                  `json:"format"`
	Manifest *journal.BundleManifest `json:"manifest"`
}

// exportBundle writes the bundle of the journal in dir to the new file out
// (journal.WriteBundle); a failed export leaves no file.
func exportBundle(fs fsys.FS, dir, out, fromArg, toArg string, warmup uint64) (*bundleResult, error) {
	from, err := parseHeight("--from", fromArg)
	if err != nil {
		return nil, err
	}
	to, err := parseHeight("--to", toArg)
	if err != nil {
		return nil, err
	}
	f, err := fs.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	m, err := journal.WriteBundle(fs, dir, f, journal.BundleOptions{From: from, To: to, Warmup: warmup})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = fs.Remove(out)
		return nil, err
	}
	return &bundleResult{Out: out, Format: "bundle", Manifest: m}, nil
}
