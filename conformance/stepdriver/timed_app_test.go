package stepdriver

import (
	"errors"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func TestTimedApplicationNeedsExactRecordedBuildAndReadyTime(t *testing.T) {
	head := &types.Header{Number: types.HeightFromUint64(7), Time: 10}
	block := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(8), ParentHash: codec.BlockHash(head)}}
	request := consensus.RequestBuild{Height: block.Header.Number, Round: types.RoundFromUint64(0), HeadTime: head.Time, BlockPeriod: 2}
	now := int64(11 * time.Second)
	for _, variant := range []string{"known", "new_round", "unrecorded"} {
		t.Run(variant, func(t *testing.T) {
			actual := request
			if variant == "new_round" {
				actual.Round = types.RoundFromUint64(1)
			}
			var reference []consensus.Output
			if variant != "unrecorded" {
				reference = []consensus.Output{request}
			}
			ledger := &timedApplicationLedger{}
			if err := ledger.produced([]consensus.Output{actual}, reference, false, now); err != nil {
				t.Fatal(err)
			}
			in := consensus.Request{Block: block}
			if err := ledger.allowed(in, "app", head, now); !errors.Is(err, ErrTraceEnvExhausted) {
				t.Fatal("early or unknown build executed", err)
			}
			err := ledger.allowed(in, "app", head, int64(12*time.Second))
			if variant == "known" {
				if err != nil {
					t.Fatal(err)
				}
				if err = ledger.allowed(in, "app", head, int64(12*time.Second)); !errors.Is(err, ErrTraceEnvExhausted) {
					t.Fatal("reservation reused", err)
				}
			} else if !errors.Is(err, ErrTraceEnvExhausted) {
				t.Fatal("invented builder answer", err)
			}
		})
	}
}
func TestTimedApplicationCommitResultNeedsActualIdenticalCommit(t *testing.T) {
	block := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(8)}}
	commit := consensus.Commit{Block: block}
	result := consensus.CommitResult{Hash: codec.BlockHash(block.Header)}
	for _, known := range []bool{false, true} {
		ledger := &timedApplicationLedger{}
		var recorded []consensus.Output
		if known {
			recorded = []consensus.Output{commit}
		}
		if err := ledger.produced([]consensus.Output{commit}, recorded, false, 0); err != nil {
			t.Fatal(err)
		}
		err := ledger.allowed(result, "app", nil, 0)
		if known && err != nil || !known && !errors.Is(err, ErrTraceEnvExhausted) {
			t.Fatal("commit proof lost", known, err)
		}
		if err = ledger.allowed(result, "app", nil, 0); !errors.Is(err, ErrTraceEnvExhausted) {
			t.Fatal("commit response reused", err)
		}
	}
}
