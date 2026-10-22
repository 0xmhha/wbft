package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestNextHeightNormalImportDelayAndReplay(t *testing.T) {
	for _, size := range []int{4, 7} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("n%d/enabled%t", size, enabled), func(t *testing.T) {
				keys := testValidators(t, size)
				nodes := make([]NodeSpec, size)
				for i := range nodes {
					nodes[i] = DefaultNode()
					nodes[i].WALSegmentBytes = 8 << 20
					if enabled {
						nodes[i].NextHeight = &runner.NextHeightLimits{Entries: 24, Bytes: 2 << 20, PerPeer: 12, PerSource: 6}
					}
				}
				nodes[size-1].ImportDelay = []time.Duration{3 * time.Second}
				var links []Link
				for _, key := range keys[:size-1] {
					links = append(links, Link{From: addrOf(key), To: addrOf(keys[size-1]), Delay: []time.Duration{10 * time.Millisecond, 2 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}})
				}
				scenario := Scenario{Name: "normal-import-receive-lane", Seed: 17, Validators: keys, Nodes: nodes, Links: links, DefaultLink: Link{Delay: []time.Duration{10 * time.Millisecond}}, Until: Stop{Height: 8, Duration: time.Minute}}
				var original *Result
				var peakEntries, peakBytes uint64
				for attempt := 0; attempt < 2; attempt++ {
					s, err := newSimulation(scenario)
					if err != nil {
						t.Fatal(err)
					}
					if attempt == 0 {
						// Read-only sampling uses the existing normal callback clock. It
						// neither changes a packet nor supplies receive/core service time.
						var sample func()
						sample = func() {
							for _, node := range s.nodes {
								if node.r != nil {
									entries, raw := node.r.NextHeightUsage()
									peakEntries = max(peakEntries, entries)
									peakBytes = max(peakBytes, raw)
									if entries > 24 || raw > 2<<20 {
										t.Fatal("owned raw reservation exceeded limits")
									}
								}
							}
							s.l.after(10*time.Millisecond, sample)
						}
						s.l.after(10*time.Millisecond, sample)
					}
					if err := s.run(context.Background()); err != nil {
						t.Fatal(err)
					}
					result := s.result()
					if len(result.Violations) != 0 {
						t.Fatal(result.Violations)
					}
					if attempt == 0 {
						original = result
					} else if !reflect.DeepEqual(original.Journals, result.Journals) || !reflect.DeepEqual(original.Events, result.Events) {
						t.Fatal("read-only quota sampling changed execution bytes")
					}
					blocks, err := NewChainSource(result.Chain)
					if err != nil {
						t.Fatal(err)
					}
					deferred, admitted, dropped := 0, 0, 0
					for _, node := range s.nodes {
						records, err := journal.ReadAll(node.fs, journalDir)
						if err != nil {
							t.Fatal(err)
						}
						reader, err := journal.OpenReader(node.fs, journalDir)
						if err != nil {
							t.Fatal(err)
						}
						walRecords, _, err := wal.ReadAll(node.fs, walDir)
						if err != nil {
							t.Fatal(err)
						}
						// Freeze the durable format-2 admission/drop tags independently of
						// the private runner constants. A sync jump may expire an admitted
						// frame before that height needs another consensus input.
						for _, record := range walRecords {
							if record.Format != 2 {
								continue
							}
							if record.Kind == 9 {
								dropped++
							}
							if record.Kind != 7 {
								continue
							}
							admitted++
							var origin struct {
								ID, Code   uint64
								Payload    []byte
								Peer       types.Address
								RecvMono   uint64
								CaptureRun string
								Capture    uint64
							}
							if err := rlp.DecodeStrict(record.Body, &origin); err != nil {
								t.Fatal(err)
							}
							frame, err := reader.ResolveCapture(origin.CaptureRun, origin.Capture)
							if err != nil || frame.Record == nil || frame.Peer != origin.Peer || frame.Record.Code != origin.Code || !bytes.Equal(frame.Record.Payload, origin.Payload) || uint64(frame.Record.Mono) != origin.RecvMono {
								t.Fatalf("durable input differs from original frame: %v", err)
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						for _, record := range records {
							switch b := record.Body.(type) {
							case *journal.SegmentRec:
								if (b.Core.NextHeight != nil) != enabled {
									t.Fatal("receive profile lost")
								}
							case *journal.StepRec:
								if b.InputKind == inputlog.KindDeferredMessage {
									deferred++
									_, e, err := journal.InspectDeferred(reader, b.Input)
									if err != nil || e.Status != "verified" {
										t.Fatalf("original frame not retained: %+v %v", e, err)
									}
								}
							}
						}
						reader, err = journal.OpenReader(node.fs, journalDir)
						if err != nil {
							t.Fatal(err)
						}
						err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(step stepdriver.StepResult) error {
							if !step.Match {
								return fmt.Errorf("node %d step %d differs", node.i, step.Step)
							}
							return nil
						})
						if err != nil {
							t.Fatal(err)
						}
					}
					if enabled && admitted == 0 {
						t.Fatalf("normal timing did not durably admit a future input: peak entries=%d raw=%d", peakEntries, peakBytes)
					}
					if !enabled && deferred != 0 {
						t.Fatal("default receiver acquired deferred inputs")
					}
					t.Logf("attempt=%d admitted=%d dropped=%d core_releases=%d peak_owned_entries=%d peak_owned_raw_bytes=%d", attempt, admitted, dropped, deferred, peakEntries, peakBytes)
				}
				if enabled && (peakEntries == 0 || peakBytes == 0) {
					t.Fatal("retained raw reservations were not observable")
				}
			})
		}
	}
}

func TestNextHeightAtomicProcessingCompatibility(t *testing.T) {
	for _, cost := range []time.Duration{0, time.Millisecond} {
		node := DefaultNode()
		node.NextHeight = &runner.NextHeightLimits{Entries: 24, Bytes: 2 << 20, PerPeer: 12, PerSource: 6}
		node.Processing = &ProcessingProfile{Workers: 1, Costs: []ProcessingCost{{Phase: runner.ProcessingCore, Kind: inputlog.KindNewHead, Samples: []time.Duration{cost}}}}
		result, err := Run(t.Context(), Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{node}, Until: Stop{Height: 2, Duration: time.Minute}}, Output{})
		if cost > 0 {
			if err == nil {
				t.Fatal("positive service time silently ignored")
			}
			continue
		}
		if err != nil || len(result.Violations) != 0 {
			t.Fatalf("zero-cost atomic profile: %v %+v", err, result)
		}
	}
}

func TestNextHeightProfileOwnershipAndExactJSON(t *testing.T) {
	limits := &runner.NextHeightLimits{Entries: 9007199254740993, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}
	node := DefaultNode()
	node.NextHeight = limits
	s, err := newSimulation(Scenario{Validators: testValidators(t, 1), Nodes: []NodeSpec{node}, Until: Stop{Duration: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	limits.Entries = 1
	if s.nodes[0].spec.NextHeight.Entries != 9007199254740993 {
		t.Fatal("caller storage changed the modeled limits")
	}
	raw, err := json.Marshal(s.nodes[0].spec.NextHeight)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded["entries"] != "9007199254740993" {
		t.Fatalf("quota integer lost precision: %s %v", raw, err)
	}
}
