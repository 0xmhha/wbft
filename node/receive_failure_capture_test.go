package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// The original source is a running no-peer Node, not model Step/queue/frame
// records. All OS copies and the optional prebuilt CLI belong to the test run.
func TestNodeReceiveFailureOriginalCaptureCLIAndBundle(t *testing.T) {
	key := testKey(0)
	config, genesis := testGenesis(t, key)
	parsed, err := types.ParseChainConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestApp(config, genesis)
	mem := fsys.NewMem()
	limits := transport.CachePolicyLimits{ReceivePending: 32, ReceivePerPeer: 8, WritePending: 32, WritePerPeer: 8}
	const run = "original-node-failure-capture"
	w, err := journal.Open(journal.Options{FS: mem, Dir: "/capture", Synchronous: true, SegmentBytes: 4096}, journal.Identity{Run: run, Core: journal.CoreOptions{
		ChainConfig: config, Self: parsed.Init.Validators[0], ProposerPolicyProfile: journal.CheckedProposerPolicyProfile, Improvements: uint64(consensus.RestartSafety), TimerTrace: journal.TimerTraceVersion,
		CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: limits}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: 2},
	}})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	n, err := New(Config{DataDir: "/data", RunID: run, CachePolicy: &limits, ReceiveFailureCache: &ReceiveFailureCacheConfig{Entries: 2}, Journal: JournalConfig{Disabled: true}}, Deps{
		App: a, Authority: a, fs: mem, key: key, Transport: &diagnosticIsolatedTransport{}, Diagnostics: &DiagnosticOptions{
			Writer: w, WALRead: wal.ReadSourceLimits{Frames: 4096, Bytes: 8 << 20}, SignerRecords: 4096, SignerBytes: 8 << 20, ApplicationBytes: 8 << 20, WALReadOnStop: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, n) })
	a.cons = n.Consensus()
	if err := n.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.waitHead(t, 2, 20*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	if n.journal != nil {
		t.Fatal("capture enabled a functional journal")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	rows, err := journal.ReadAll(mem, "/capture")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[journal.Kind]int{}
	for _, row := range rows {
		counts[row.Kind]++
	}
	if counts[journal.KindCoreStep] == 0 || counts[journal.KindStep] != 0 || counts[journal.KindInboxFailureHit] != 0 {
		t.Fatal("actual diagnostic source acquired invented functional steps or hits", counts)
	}
	bounds := journal.ReceiveFailureLimits{Caches: 8, Inbox: journal.InboxLimits{
		Core: journal.CoreSourceLimits{Records: 20000, Runs: 32, Steps: 20000, Environments: 20000, Outputs: 100000, Bytes: 64 << 20}, Operations: 20000, Entries: 1000, Peers: 100, Frames: 1000, Bytes: 64 << 20,
	}}
	expected, checkErr := journal.CheckReceiveFailureSources(rows, bounds)
	if checkErr != nil || expected.Status != "consistent" && expected.Status != "unavailable" {
		t.Fatal("normal original capture contradicted its sources", expected, checkErr)
	}
	if expected.PhysicalStatus != "unavailable" || expected.VerifiedFailures != 0 || expected.ConsumedFailures != 0 {
		t.Fatal("normal no-peer capture became physical or failed-check evidence", expected)
	}
	t.Logf("original_node_capture api_status=%s api_reason=%s records=%d core_steps=%d failure_events=%d verified_failures=0 consumed_failures=0", expected.Status, expected.Reason, len(rows), counts[journal.KindCoreStep], counts[journal.KindReceiveFailure])
	t.Run("externalCLI", func(t *testing.T) {
		binary := os.Getenv("WBFT_OWNED_JOURNAL_BIN")
		if binary == "" {
			t.Skip("prebuilt CLI supplied by the owned integration runner; Node/library/bundle checks still run")
		}
		if !filepath.IsAbs(binary) {
			t.Fatal("CLI binary path is not absolute")
		}
		info, err := os.Stat(binary)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("prebuilt CLI unavailable", err)
		}
		directory := t.TempDir()
		entries, err := mem.ReadDir("/capture")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if filepath.Base(entry) != entry {
				t.Fatal("unexpected path inside original capture")
			}
			raw, err := mem.ReadFile(filepath.Join("/capture", entry))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, entry), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		limitFile := filepath.Join(t.TempDir(), "limits.json")
		raw, err := json.Marshal(bounds)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(limitFile, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), binary, "check-receive-failures", "--dir", directory, "--source-limits", limitFile)
		output, err := command.CombinedOutput()
		actualExit := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("cannot execute prebuilt original CLI", err)
			}
			actualExit = exit.ExitCode()
		}
		expectedExit := 0
		if expected.Status == "unavailable" {
			expectedExit = 69
		}
		if actualExit != expectedExit {
			t.Fatalf("CLI/API outcome mismatch: exit=%d expected=%d output=%s", actualExit, expectedExit, output)
		}
		var actual journal.ReceiveFailureCheck
		if err := json.Unmarshal(output, &actual); err != nil {
			t.Fatal("CLI did not return the complete source result", err)
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Fatal("CLI changed source scope, reason or counts", expected, actual)
		}
		t.Logf("original_capture_CLI_api_JSON_equal=true exit=%d status=%s crypto_failure_hit=false", actualExit, actual.Status)
		for _, consumer := range []struct {
			variable string
			name     string
			extra    []string
		}{
			{"WBFT_OWNED_ANALYZER_BIN", "analyzer", nil},
			{"WBFT_OWNED_INSPECTOR_BIN", "inspector", []string{"--checker", binary}},
		} {
			selected := os.Getenv(consumer.variable)
			if selected == "" {
				continue
			}
			if !filepath.IsAbs(selected) {
				t.Fatal("consumer binary path is not absolute")
			}
			arguments := []string{"receive-failures", "--journal", directory, "--source-limits", limitFile}
			arguments = append(arguments, consumer.extra...)
			if consumer.name == "inspector" {
				original, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(original)
				arguments = append(arguments, "--checker-sha256", hex.EncodeToString(digest[:]))
			}
			command := exec.CommandContext(t.Context(), selected, arguments...) //nolint:gosec // explicitly selected owned integration binaries
			output, err := command.CombinedOutput()
			consumerExit := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal("cannot execute owned consumer", err)
				}
				consumerExit = exit.ExitCode()
			}
			if consumerExit != expectedExit {
				t.Fatalf("%s source exit=%d expected=%d output=%s", consumer.name, consumerExit, expectedExit, output)
			}
			var consumed journal.ReceiveFailureCheck
			if err := json.Unmarshal(output, &consumed); err != nil || !reflect.DeepEqual(consumed, expected) {
				t.Fatal("consumer changed original full source report", consumer.name, consumed, expected, err)
			}
			t.Logf("original_capture_%s_api_JSON_equal=true exit=%d status=%s crypto_failure_hit=false", consumer.name, consumerExit, consumed.Status)
		}

	})
	var bundle bytes.Buffer
	manifest, err := journal.WriteBundle(mem, "/capture", &bundle, journal.BundleOptions{})
	if err != nil {
		t.Fatal("actual diagnostic capture could not be bundled without invented StepRec", err)
	}
	restoredManifest, err := journal.ReadBundle(bytes.NewReader(bundle.Bytes()), mem, "/retained")
	if err != nil || !reflect.DeepEqual(manifest, restoredManifest) {
		t.Fatal("bundle manifest changed", err)
	}
	retained, err := journal.ReadAll(mem, "/retained")
	if err != nil || len(retained) == 0 {
		t.Fatal("bundle has no retained original source records", err)
	}
	// An unbounded bundle preserves this whole original capture, not merely
	// an equal verdict over a smaller prefix. Compare both decoded values and
	// each selected original segment/index against the manifest and restore.
	if !reflect.DeepEqual(rows, retained) {
		t.Fatal("unbounded bundle changed original record count or values", len(rows), len(retained))
	}
	files, err := mem.ReadDir("/capture")
	if err != nil || len(manifest.Files) != len(files) {
		t.Fatal("unbounded bundle omitted original files", len(manifest.Files), len(files), err)
	}
	for _, file := range manifest.Files {
		original, err := mem.ReadFile(filepath.Join("/capture", file.Name))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := mem.ReadFile(filepath.Join("/retained", file.Name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(original)
		if !bytes.Equal(original, restored) || file.Size != int64(len(original)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("bundle changed original segment/index bytes or hash", file.Name)
		}
	}
	retainedResult, retainedErr := journal.CheckReceiveFailureSources(retained, bounds)
	if retainedErr != nil || !reflect.DeepEqual(retainedResult, expected) {
		t.Fatal("bundle changed the original source outcome", retainedResult, expected, retainedErr)
	}
	t.Logf("original_capture_bundle status=%s source_records=%d retained_records=%d files=%d", retainedResult.Status, len(rows), len(retained), len(manifest.Files))
}
