package schema

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestReceiveFailureStartupDeclaration(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		for _, entries := range []uint64{1, transport.InmemoryMessages} {
			fields := map[string]any{"impl": "wbft", "mode": "standalone", "sign_floor": nil, "wal_recovery": map[string]any{"records": 0, "torn_bytes": 0, "corrupted": 0}}
			policy := map[string]any{"profile": transport.ReceiveFailureProfile, "entries": entries, "active": active}
			fields["receive_failure_cache"] = policy
			validate := func() error {
				var raw bytes.Buffer
				w := event.NewWriter(&raw, types.Address{1}, "failure-policy-shape")
				if err := w.Write(event.Record{Kind: event.NodeStart, Fields: fields}, event.Stamp{Wall: time.Unix(1700000000, 0)}); err != nil {
					return err
				}
				return s.Validate(raw.Bytes())
			}
			if err := validate(); err != nil {
				t.Fatal("ordinary functional declaration rejected", err)
			}
			// These are detached event-shape checks, not modified packets,
			// signatures, runtime inputs or diagnostic capability claims.
			for _, missing := range []string{"profile", "entries", "active"} {
				value := policy[missing]
				delete(policy, missing)
				if validate() == nil {
					t.Fatal("incomplete functional declaration accepted", missing)
				}
				policy[missing] = value
			}
			for _, invalid := range []uint64{0, transport.InmemoryMessages + 1} {
				policy["entries"] = invalid
				if validate() == nil {
					t.Fatal("out-of-range declared entry bound accepted", invalid)
				}
			}
			policy["entries"] = entries
			policy["profile"] = "unsupported"
			if validate() == nil {
				t.Fatal("unknown functional profile accepted")
			}
		}
	}
}
