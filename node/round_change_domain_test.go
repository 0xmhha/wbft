package node

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// Two ordinary starts retain the same actual genesis, key and full history.
func TestNodeRoundChangeDomainNormalCreateAndReopen(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config["wbftRules"] = json.RawMessage(`{"consensusRules":{"roundChangeDomain":3}}`)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	genesis.Header.Time = 999
	a := newTestApp(raw, genesis)
	fs := fsys.NewMem()
	deps := Deps{App: a, Authority: a, Transport: cacheIsolatedTransport{}, fs: fs, key: key}
	for _, run := range []string{"domain-create", "domain-reopen"} {
		cfg := Config{DataDir: "/domain-node", RunID: run}
		n, err := New(cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = n.Stop() })
		a.cons = n.Consensus()
		if !a.Head().Number.IsUint64() {
			t.Fatal("normal fixture height exceeds its bound")
		}
		next := a.Head().Number.RefLow64() + 1
		if err := n.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.waitHead(t, next, 5*time.Second)
		if err := n.Stop(); err != nil {
			t.Fatal(err)
		}
		state, err := fs.ReadFile("/domain-node/privval/state")
		if err != nil || len(state) == 0 || state[0] != 2 {
			t.Fatal("normal Node signer did not retain domain format 2", err)
		}
		records, _, err := wal.ReadAll(fs, "/domain-node/wal")
		if err != nil || len(records) == 0 || records[0].Format != 6 {
			t.Fatal("normal Node history omitted functional format 6", err)
		}
		observed, err := journal.ReadAll(fs, "/domain-node/journal")
		if err != nil {
			t.Fatal(err)
		}
		segments := 0
		for _, record := range observed {
			if segment, ok := record.Body.(*journal.SegmentRec); ok {
				segments++
				if len(segment.Core.DomainBytes) == 0 || segment.ValidateDomainIdentity() != nil {
					t.Fatal("actual Node segment lost its bound domain")
				}
			}
		}
		if segments == 0 {
			t.Fatal("normal Node omitted its source segment")
		}
	}
}

type domainDeclarationOnlyWriter struct{ core journal.CoreOptions }

func (*domainDeclarationOnlyWriter) Put(journal.Record) {}
func (*domainDeclarationOnlyWriter) Close() error       { return nil }
func (*domainDeclarationOnlyWriter) CaptureRun() string { return "domain-preflight" }
func (w *domainDeclarationOnlyWriter) CoreDeclaration() journal.CoreOptions {
	return w.core.Copy()
}

// An unsigned declaration with no domain witness is refused before opening
// any Node data store. The fixture never starts an actor or changes a packet.
func TestNodeRoundChangeDomainDiagnosticPreflightBeforeWriters(t *testing.T) {
	key := testKey(0)
	raw, genesis := testGenesis(t, key)
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config["wbftRules"] = json.RawMessage(`{"consensusRules":{"roundChangeDomain":3}}`)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := types.ParseChainConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	limits := transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}
	writer := &domainDeclarationOnlyWriter{core: journal.CoreOptions{Self: parsed.Init.Validators[0], ChainConfig: raw,
		Improvements: uint64(consensus.RestartSafety), ProposerPolicyProfile: journal.CheckedProposerPolicyProfile,
		CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}}}
	fs := fsys.NewMem()
	a := newTestApp(raw, genesis)
	n, err := New(Config{DataDir: "/domain-preflight", RunID: "domain-preflight", CachePolicy: &limits, Journal: JournalConfig{Disabled: true}}, Deps{
		App: a, Authority: a, fs: fs, key: key, Transport: &diagnosticIsolatedTransport{},
		Diagnostics: &DiagnosticOptions{Writer: writer, WALRead: wal.ReadSourceLimits{Frames: 100, Bytes: 1 << 20},
			SignerRecords: 100, SignerBytes: 1 << 20, ApplicationBytes: 1 << 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = n.Start(t.Context())
	if err == nil {
		_ = n.Stop()
		t.Fatal("missing diagnostic domain witness reached a live Node")
	}
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), types.ErrRoundChangeDomain.Error()) {
		t.Fatal("fixture was refused for an unrelated reason", err)
	}
	if _, err := fs.ReadDir("/domain-preflight"); !fsys.IsNotExist(err) {
		t.Fatal("diagnostic refusal happened after opening a Node store", err)
	}
}
