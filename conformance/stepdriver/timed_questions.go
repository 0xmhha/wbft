package stepdriver

import (
	"crypto/sha256"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

type timedQuestionKey struct {
	context answerContext
	digest  [32]byte
}
type TimedQuestionSource struct {
	Source TimedSource
	Output uint64
}
type timedQuestionPool map[timedQuestionKey]TimedQuestionSource

func questionDigest(output consensus.Output) ([32]byte, bool, error) {
	switch output.(type) {
	case consensus.RequestBuild, consensus.Commit:
	default:
		return [32]byte{}, false, nil
	}
	raw, err := inputlog.EncodeOutputs([]consensus.Output{output})
	return sha256.Sum256(raw), true, err
}
func newTimedQuestionPool(entries []timedSourceEntry, reference map[TimedSource][]consensus.Output) (timedQuestionPool, error) {
	pool := timedQuestionPool{}
	for _, entry := range entries {
		context := answerContextOf(entry.source.Writer, entry.record)
		for index, output := range reference[entry.source] {
			digest, question, err := questionDigest(output)
			if err != nil {
				return nil, err
			}
			if question {
				key := timedQuestionKey{context, digest}
				if _, exists := pool[key]; !exists {
					pool[key] = TimedQuestionSource{Source: entry.source, Output: uint64(index) + 1}
				}
			}
		}
	}
	return pool, nil
}
func (p timedQuestionPool) match(context answerContext, outputs []consensus.Output) ([]consensus.Output, []TimedQuestionSource, error) {
	var questions []consensus.Output
	var sources []TimedQuestionSource
	for _, output := range outputs {
		digest, question, err := questionDigest(output)
		if err != nil {
			return nil, nil, err
		}
		if !question {
			continue
		}
		if source, exists := p[timedQuestionKey{context, digest}]; exists {
			questions = append(questions, output)
			sources = append(sources, source)
		}
	}
	return questions, sources, nil
}
