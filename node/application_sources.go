package node

import (
	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

func (f *sessionFrameRecorder) beginApplication(req app.FinalizeRequest, limit uint64) *journal.ApplicationRec {
	s := &journal.ApplicationRec{Version: journal.ApplicationSourceVersion, EntryMono: uint64(f.clock.Mono()), EntryWallNs: uint64(f.clock.Now().UnixNano())}
	if req.Source == nil {
		s.Unavailable = "owner_unavailable"
	} else {
		s.Source = *req.Source
		if s.Source.Run == "" || s.Source.Engine == 0 || s.Source.Step == 0 || s.Source.Output == 0 || s.Source.Task == 0 {
			s.Unavailable = "owner_unavailable"
		}
	}
	var err error
	s.Arguments, err = inputlog.EncodeOutputs([]consensus.Output{consensus.Commit{Block: req.Block, Round: req.Round}})
	if err != nil {
		s.Unavailable = "argument_encoding"
	}
	if uint64(len(s.Arguments)) > limit {
		s.Arguments, s.Unavailable = nil, "byte_limit"
	}
	return s
}
func (f *sessionFrameRecorder) finishApplication(s *journal.ApplicationRec, response app.FinalizeResponse, err error) {
	s.Mono, s.WallNs = uint64(f.clock.Mono()), uint64(f.clock.Now().UnixNano())
	s.Result = "error"
	if err == nil {
		s.Result, s.Hash = "ok", response.Hash
		if response.AlreadyHead {
			s.AlreadyHead = 1
		}
	}
	f.jw.Put(journal.Record{Body: s})
}
