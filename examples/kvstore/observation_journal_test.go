package kvstore

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/node"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type observationTraceBlocks struct {
	headers map[string]*types.Header
	blocks  map[types.Hash]*types.Block
}

// Only detached segment metadata changes; captures and core inputs stay intact.
type observationMetadataCopy struct {
	*journal.Reader
	change func(*journal.SegmentRec)
}

func (r observationMetadataCopy) Next() (journal.Record, error) {
	record, err := r.Reader.Next()
	if err != nil {
		return record, err
	}
	if segment, ok := record.Body.(*journal.SegmentRec); ok {
		copy := *segment
		if copy.Core.Observation != nil {
			options := *copy.Core.Observation
			options.Checkpoint = bytes.Clone(options.Checkpoint)
			copy.Core.Observation = &options
		}
		r.change(&copy)
		record.Body = &copy
	}
	return record, nil
}

func (b observationTraceBlocks) HeaderByNumber(n types.Height) (*types.Header, error) {
	if h := b.headers[n.String()]; h != nil {
		return h, nil
	}
	return nil, fmt.Errorf("missing observation trace height %s", n.String())
}

func (b observationTraceBlocks) BlockByHash(hash types.Hash) (*types.Block, error) {
	if block := b.blocks[hash]; block != nil {
		return block, nil
	}
	return nil, fmt.Errorf("missing observation trace block %x", hash)
}

// This pair uses ordinary own-key network traffic and normal shutdown/reopen.
// It replays every writer's full core trace, including the post-activation run.
func TestNormalObservationJournalOffOnAndRestartReplay(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			configure := func(g *Genesis) *node.ObservationConfig {
				if !enabled {
					return nil
				}
				options := normalObservationPolicy(t, g)
				options.ReplayHeaders = 4 // The restart is farther than this from activation.
				return options
			}
			network := newTestNetConfigured(t, 4, configure, false)
			owner := types.Address{0xc1}
			submit(t, network.nodes[0], Tx{From: owner, Nonce: 0, Key: "journal-observation", Value: "before"})
			waitFor(t, "normal journal carriers", 60*time.Second, func() bool {
				for _, nd := range network.nodes {
					if nd.App.Head().Number.CmpUint64(12) < 0 || nd.App.Nonce(owner) != 1 {
						return false
					}
				}
				return true
			})
			for i, nd := range network.nodes {
				network.nodes[i] = nil
				if err := nd.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			for i := range network.nodes {
				network.open(i)
			}
			for i := range network.nodes {
				network.start(i)
			}
			submit(t, network.nodes[0], Tx{From: owner, Nonce: 1, Key: "journal-observation", Value: "after"})
			waitFor(t, "normal journal restart", 60*time.Second, func() bool {
				for _, nd := range network.nodes {
					if nd.App.Head().Number.CmpUint64(20) < 0 || nd.App.Nonce(owner) != 2 {
						return false
					}
				}
				return true
			})
			closed := append([]*Node(nil), network.nodes...)
			for i, nd := range closed {
				network.nodes[i] = nil
				if err := nd.Stop(); err != nil {
					t.Fatal(err)
				}
			}
			for i, nd := range closed {
				blocks := observationTraceBlocks{headers: map[string]*types.Header{}, blocks: map[types.Hash]*types.Block{}}
				if nd.App.Head().Number.CmpUint64(256) > 0 {
					t.Fatal("normal fixture exceeded its explicit block budget")
				}
				for number := uint64(0); nd.App.Head().Number.CmpUint64(number) >= 0; number++ {
					block := nd.App.BlockByNumber(number)
					if block == nil {
						t.Fatal("normal canonical block missing")
					}
					blocks.headers[block.Header.Number.String()] = block.Header
					blocks.blocks[codec.BlockHash(block.Header)] = block
				}
				dir := filepath.Join(network.homes[i], "consensus", "journal")
				records, err := journal.ReadAll(fsys.OS{}, dir)
				if err != nil {
					t.Fatal(err)
				}
				runs := map[string]bool{}
				checkpoint := false
				var restartCheckpoint []byte
				for _, record := range records {
					if segment, ok := record.Body.(*journal.SegmentRec); ok {
						runs[segment.Run] = true
						if (segment.Core.Observation != nil) != enabled {
							t.Fatal("journal observation declaration differs from the normal node")
						}
						if enabled && len(segment.Core.Observation.Checkpoint) != 0 {
							checkpoint = true
							restartCheckpoint = bytes.Clone(segment.Core.Observation.Checkpoint)
						}
					}
				}
				if len(runs) != 2 || enabled && !checkpoint {
					t.Fatal("both normal writer runs and the restart checkpoint were not recorded")
				}
				reader, err := journal.OpenReader(fsys.OS{}, dir)
				if err != nil {
					t.Fatal(err)
				}
				steps := 0
				err = stepdriver.RunTrace(reader, stepdriver.TraceOptions{Blocks: blocks}, func(step stepdriver.StepResult) error {
					steps++
					if !step.Match {
						return fmt.Errorf("normal node %d writer %s step %d digest differs", i, step.WriterRun, step.Step)
					}
					return nil
				})
				if err != nil || steps < 20 {
					t.Fatalf("normal node %d: %d steps: %v", i, steps, err)
				}
				t.Logf("node %d: observation=%v writers=%d matched_steps=%d", i, enabled, len(runs), steps)
				if enabled && i == 0 {
					for _, test := range []struct {
						name   string
						change func(*journal.SegmentRec)
					}{
						{"missing-profile", func(s *journal.SegmentRec) { s.Core.Observation = nil }},
						{"unknown-profile", func(s *journal.SegmentRec) { s.Core.Observation.Profile++ }},
						{"different-policy", func(s *journal.SegmentRec) { s.Core.Observation.Retention = "4" }},
						{"different-genesis", func(s *journal.SegmentRec) { s.GenesisHash[0] ^= 1 }},
						{"missing-restart-checkpoint", func(s *journal.SegmentRec) { s.Core.Observation.Checkpoint = nil }},
						{"ahead-checkpoint", func(s *journal.SegmentRec) { s.Core.Observation.Checkpoint = bytes.Clone(restartCheckpoint) }},
						{"changed-checkpoint", func(s *journal.SegmentRec) {
							if len(s.Core.Observation.Checkpoint) != 0 {
								s.Core.Observation.Checkpoint[len(s.Core.Observation.Checkpoint)-1] ^= 1
							}
						}},
					} {
						reader, err := journal.OpenReader(fsys.OS{}, dir)
						if err != nil {
							t.Fatal(err)
						}
						err = stepdriver.RunTrace(observationMetadataCopy{reader, test.change}, stepdriver.TraceOptions{Blocks: blocks}, func(stepdriver.StepResult) error { return nil })
						if err == nil {
							t.Fatalf("closed segment metadata accepted: %s", test.name)
						}
						t.Logf("closed metadata %s refused: %v", test.name, err)
					}
				}
			}
		})
	}
}
