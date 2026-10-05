package logcat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestProfile: the profile maps every catalog kind and LOG_CONFIG, a line
// is identified by its message, level and module alone, and the ID is the
// digest of the entries.
func TestProfile(t *testing.T) {
	p := BuildProfile()
	kinds := map[string]bool{}
	lines := map[[3]string]string{}
	for _, e := range p.Entries {
		kinds[e.Kind] = true
		k := [3]string{e.Msg, e.Level, e.Module}
		if prev, ok := lines[k]; ok {
			t.Fatalf("%s and %s have the same line %v", prev, e.Kind, k)
		}
		lines[k] = e.Kind
	}
	for _, k := range append(EventKinds(), "LOG_CONFIG") {
		if !kinds[k] {
			t.Fatalf("no entry for %s", k)
		}
	}
	if len(p.Entries) != len(EventKinds())+1 || p.Format != ProfileFormat {
		t.Fatalf("profile %+v", p)
	}
	b, err := json.Marshal(p.Entries)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if want := "wbft@" + hex.EncodeToString(sum[:6]); p.ID != want || ProfileID() != want {
		t.Fatalf("id %s, want %s", p.ID, want)
	}
	if e := p.Entries[0]; e.Kind != "BACKLOG" || e.Level != "trace" || e.Module != "consensus.msg" {
		t.Fatalf("first entry %+v", e)
	}
}
