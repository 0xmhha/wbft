// Package buildmeta reports the WBFT module identity embedded in a binary.
package buildmeta

import "runtime/debug"

// Version returns the dependency version or main-module VCS revision. Local
// replacements without a version remain unknown rather than naming the host.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return version(info)
}
func version(info *debug.BuildInfo) string {
	const path = "github.com/0xmhha/wbft"
	for _, d := range info.Deps {
		if d.Path == path {
			if d.Replace != nil {
				if d.Replace.Version != "" {
					return d.Replace.Version
				}
				return "unknown"
			}
			if d.Version != "" {
				return d.Version
			}
			return "unknown"
		}
	}
	if info.Main.Path == path {
		revision := ""
		modified := false
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				revision = s.Value
			}
			if s.Key == "vcs.modified" && s.Value == "true" {
				modified = true
			}
		}
		if revision != "" {
			if modified {
				return revision + "-modified"
			}
			return revision
		}
		if info.Main.Version != "" {
			return info.Main.Version
		}
	}
	return "unknown"
}
