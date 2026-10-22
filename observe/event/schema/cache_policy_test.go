package schema

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func TestCachePolicyStartupDeclaration(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		var raw bytes.Buffer
		w := event.NewWriter(&raw, types.Address{1}, "policy-run")
		fields := map[string]any{"impl": "wbft", "mode": "standalone", "profile": "compat", "sign_floor": nil,
			"wal_recovery": map[string]any{"records": 0, "torn_bytes": 0, "corrupted": 0},
			"transport_cache": map[string]any{"profile": transport.CachePolicyProfile, "active": active,
				"limits": transport.CachePolicyLimits{ReceivePending: 9007199254740993, ReceivePerPeer: 8, WritePending: 64, WritePerPeer: 16}}}
		if err := w.Write(event.Record{Kind: event.NodeStart, Fields: fields}, event.Stamp{Wall: time.Unix(1700000000, 0)}); err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(raw.Bytes()); err != nil {
			t.Fatal("startup cache declaration is outside the public event schema", err)
		}
		for _, missing := range []string{"profile", "active", "limits"} {
			policy := fields["transport_cache"].(map[string]any)
			kept := policy[missing]
			delete(policy, missing)
			raw.Reset()
			if err := w.Write(event.Record{Kind: event.NodeStart, Fields: fields}, event.Stamp{Wall: time.Unix(1700000000, 0)}); err != nil {
				t.Fatal(err)
			}
			if s.Validate(raw.Bytes()) == nil {
				t.Fatal("incomplete declaration accepted", missing)
			}
			policy[missing] = kept
		}
	}
}
