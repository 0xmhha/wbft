package runner

import (
	"bytes"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/observe/journal"
)

// SignerCallObserver sees detached runner-to-signer/WAL call results, after the
// original operation. It does not enable functional replay or signing itself.
type SignerCallObserver interface{ ObserveSignerCall(journal.SignerCallRec) }

func (r *Runner) newSignerCall(sc *stepCtx, b consensus.Broadcast) *journal.SignerCallRec {
	if r.d.SignerCalls == nil {
		return nil
	}
	s := &journal.SignerCallRec{Version: journal.SignerCallSourceVersion, EngineRun: r.engineRun, Step: sc.step, Output: sc.output, RequestCode: uint64(b.Msg.Code), SealData: bytes.Clone(b.SealData), WAL: r.lastWALReadSource}
	if b.BadBlockReleased {
		s.BadBlockReleased = 1
	}
	m := *b.Msg
	m.Signature, m.Seal = nil, nil
	var err error
	s.Request, err = codec.EncodeMessage(&m)
	if err != nil {
		s.Unavailable = "request_encoding"
	}
	if r.d.WAL != nil {
		s.WALPresent = 1
	} else {
		s.Unavailable = "wal_missing"
	}
	if s.WAL.Log == 0 && s.Unavailable == "" {
		s.Unavailable = "wal_read_missing"
	}
	return s
}
func (r *Runner) signVoteSource(request privval.VoteRequest, s *journal.SignerCallRec) (privval.VoteSignature, error) {
	if s == nil {
		return r.d.Signer.SignVote(request)
	}
	var sig privval.VoteSignature
	var err error
	if signer, ok := r.d.Signer.(interface {
		SignVoteWithSource(privval.VoteRequest) (privval.VoteSignature, privval.SourceRef, error)
	}); ok {
		sig, s.Source, err = signer.SignVoteWithSource(request)
	} else {
		sig, err = r.d.Signer.SignVote(request)
	}
	if s.Source.Namespace == "" || s.Source.Signer == 0 || s.Source.Sequence == 0 {
		s.Unavailable = "source_missing"
	}
	s.Signature, s.Seal = bytes.Clone(sig.Signature), bytes.Clone(sig.Seal)
	if sig.Reused {
		s.Reused = 1
	}
	return sig, err
}
func (r *Runner) finishSignerCall(s *journal.SignerCallRec) {
	if s == nil {
		return
	}
	s.Mono, s.WallNs = uint64(r.d.Clock.Mono()), uint64(r.d.Clock.Now().UnixNano())
	r.d.SignerCalls.ObserveSignerCall(*s)
}
