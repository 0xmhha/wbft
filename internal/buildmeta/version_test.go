package buildmeta

import (
	"runtime/debug"
	"testing"
)

func TestVersionBindsWBFTRatherThanHost(t *testing.T) {
	const path = "github.com/0xmhha/wbft"
	for _, c := range []struct {
		info debug.BuildInfo
		want string
	}{{debug.BuildInfo{Main: debug.Module{Path: path}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "synthetic-core"}}}, "synthetic-core"}, {debug.BuildInfo{Main: debug.Module{Path: "synthetic-host"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "host"}}, Deps: []*debug.Module{{Path: path, Version: "v0.0.0-synthetic"}}}, "v0.0.0-synthetic"}, {debug.BuildInfo{Deps: []*debug.Module{{Path: path, Version: "old", Replace: &debug.Module{Path: "../local"}}}}, "unknown"}, {debug.BuildInfo{}, "unknown"}} {
		if got := version(&c.info); got != c.want {
			t.Fatal(got, c.want)
		}
	}
}

func TestModifiedCoreCannotClaimTheCleanRevision(t *testing.T) {
	info := debug.BuildInfo{Main: debug.Module{Path: "github.com/0xmhha/wbft"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "synthetic-core"}, {Key: "vcs.modified", Value: "true"}}}
	if got := version(&info); got != "synthetic-core-modified" {
		t.Fatal(got)
	}
}
