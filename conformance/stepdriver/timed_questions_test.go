package stepdriver

import (
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestTimedQuestionsRequireFullQuestionAndOriginalContext(t *testing.T) {
	source := TimedSource{Writer: "synthetic", Engine: 1, Step: 2, Ordinal: 3}
	record := &journal.StepRec{HeadNumber: types.HeightFromUint64(7), HeadHash: types.Hash{1}, ValsetDigest: types.Hash{2}}
	original := consensus.RequestBuild{Height: types.HeightFromUint64(8), Round: types.RoundFromUint64(1), HeadTime: 10, BlockPeriod: 2}
	pool, err := newTimedQuestionPool([]timedSourceEntry{{source: source, record: record}}, map[TimedSource][]consensus.Output{source: {original}})
	if err != nil {
		t.Fatal(err)
	}
	context := answerContextOf(source.Writer, record)
	for _, variant := range []string{"known", "writer", "engine", "head", "valset", "round", "period"} {
		current, question := context, original
		switch variant {
		case "writer":
			current.writer = "other"
		case "engine":
			current.engine = 2
		case "head":
			current.hash = types.Hash{3}
		case "valset":
			current.valset = types.Hash{3}
		case "round":
			question.Round = types.RoundFromUint64(2)
		case "period":
			question.BlockPeriod = 3
		}
		questions, sources, err := pool.match(current, []consensus.Output{question})
		if err != nil {
			t.Fatal(err)
		}
		if variant == "known" {
			if len(questions) != 1 || len(sources) != 1 || sources[0].Source != source || sources[0].Output != 1 {
				t.Fatal("original question provenance lost", questions, sources)
			}
		} else if len(questions) != 0 || len(sources) != 0 {
			t.Fatal("unknown question promoted", variant, sources)
		}
	}
}
