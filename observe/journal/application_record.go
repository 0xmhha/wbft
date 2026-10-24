package journal

import (
	"fmt"
	"math"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

const ApplicationSourceVersion uint64 = 1

// ApplicationRec describes one original application call. Arguments contain
// the Commit output before the call; Result is a class, never an error string.
// A successful response alone does not prove execution or physical storage.
type ApplicationRec struct {
	Version                              uint64
	Source                               app.FinalizeSource
	Arguments                            []byte
	Hash                                 types.Hash
	AlreadyHead                          uint64
	Result                               string
	EntryMono, Mono, EntryWallNs, WallNs uint64
	Unavailable                          string
}
type applicationRLP struct {
	Format, JSeq uint64
	Source       ApplicationRec
}

// Commit decodes an owned copy of the original canonical request. It does not
// authenticate the source or include an observed application response.
func (s *ApplicationRec) Commit() (consensus.Commit, error) {
	if !validApplicationRec(s) || s.Unavailable != "" {
		return consensus.Commit{}, ErrApplicationSource
	}
	return decodeApplicationCommit(s.Arguments)
}

func validApplicationRec(s *ApplicationRec) bool {
	if s.Version != ApplicationSourceVersion || s.EntryMono > s.Mono || s.Mono > math.MaxInt64 || s.AlreadyHead > 1 {
		return false
	}
	if s.Result != "ok" && s.Result != "error" {
		return false
	}
	if s.Result != "ok" && s.AlreadyHead != 0 {
		return false
	}
	switch s.Unavailable {
	case "", "owner_unavailable", "argument_encoding", "byte_limit":
	default:
		return false
	}
	if s.Unavailable == "" && (s.Source.Run == "" || s.Source.Engine == 0 || s.Source.Step == 0 || s.Source.Output == 0 || s.Source.Task == 0 || len(s.Arguments) == 0) {
		return false
	}
	return true
}
func encodeApplicationRec(s *ApplicationRec, jseq uint64) ([]byte, error) {
	if !validApplicationRec(s) {
		return nil, fmt.Errorf("journal: invalid application source")
	}
	return rlp.Encode(&applicationRLP{Format, jseq, *s})
}
func decodeApplicationRec(raw []byte) (Record, error) {
	var w applicationRLP
	if err := rlp.DecodeStrict(raw, &w); err != nil || w.Format != Format || !validApplicationRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid application source", ErrRecord)
	}
	return Record{Kind: KindApplication, JSeq: w.JSeq, Body: &w.Source}, nil
}
