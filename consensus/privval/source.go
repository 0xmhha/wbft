package privval

import (
	"bytes"
	"errors"
	"sync/atomic"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

const SourceVersion uint64 = 1

type SourceRef struct {
	Namespace        string
	Signer, Sequence uint64
}

// SourceOptions configure optional public-state observations. The namespace and
// bounds are frozen at construction. Callbacks run after the signer mutex is
// released and may arrive out of order; Sequence preserves its original order.
// Bytes bounds retained spans, not original signing/encoding allocations or heap.
type SourceOptions struct {
	Namespace      string
	Records, Bytes uint64
	Observe        func(Source)
}

// Source holds only public logical state, requests, signatures and the original
// atomic-write result. It never includes a secret key, host path or error text.
// An initial state is a conditional witness, not proof of historical signatures
// or physical persistence before this observed signer lifetime.
type Source struct {
	Version           uint64
	Ref               SourceRef
	Address           types.Address
	BLSPublicKey      []byte
	Action            string
	Before, After     []byte
	RequestCode       uint64
	Request, SealData []byte
	BadBlockReleased  uint64
	Floor             string
	Signature, Seal   []byte
	Reused            uint64
	Result            string
	WriteAttempted    uint64
	Write             []byte
	WriteResult       string
	Unavailable       string
}

type sourceState struct {
	options          *SourceOptions
	signer, sequence uint64
	exhausted        bool
	active           *Source
	span             uint64
}

var sourceIDs atomic.Uint64

func nextSourceID() uint64 {
	for {
		old := sourceIDs.Load()
		if old == ^uint64(0) {
			return 0
		}
		if sourceIDs.CompareAndSwap(old, old+1) {
			return old + 1
		}
	}
}

// NewKeySignerWithOptions keeps NewKeySigner's original behavior and adds only
// the explicitly requested diagnostic observer.
func NewKeySignerWithOptions(opt Options, secret []byte, stateFile string) (*FileSigner, error) {
	fs := opt.FS
	if fs == nil {
		fs = fsys.OS{}
	}
	s, err := newSigner(fs, opt.Faults, secret, stateFile)
	if err != nil {
		return nil, err
	}
	s.initializeSource(opt.Sources)
	return s, nil
}

func (s *FileSigner) initializeSource(options *SourceOptions) {
	if options == nil || options.Observe == nil {
		return
	}
	copy := *options
	s.source.options = &copy
	s.source.signer = nextSourceID()
	s.mu.Lock()
	r := s.beginSource("initial")
	s.finishSourceLocked(r, VoteSignature{}, nil)
	s.mu.Unlock()
	s.publishSource(r)
}
func (s *FileSigner) beginSource(action string) *Source {
	o := &s.source
	if o.options == nil {
		return nil
	}
	if o.sequence == ^uint64(0) {
		o.exhausted = true
	} else if !o.exhausted {
		o.sequence++
	}
	seq := o.sequence
	if o.exhausted {
		seq = 0
	}
	r := &Source{Version: SourceVersion, Ref: SourceRef{o.options.Namespace, o.signer, seq}, Address: s.addr, BLSPublicKey: bytes.Clone(s.blsPub), Action: action}
	o.span = uint64(len(r.BLSPublicKey))
	o.active = r
	if r.Ref.Namespace == "" {
		r.Unavailable = "namespace_missing"
	}
	if r.Ref.Signer == 0 || r.Ref.Sequence == 0 {
		r.Unavailable = "metadata_exhausted"
	}
	r.Before = s.sourceStateBytes(r, s.st)
	return r
}
func (s *FileSigner) sourceRetain(r *Source, b []byte) []byte {
	if r == nil || r.Unavailable != "" {
		return nil
	}
	limit := s.source.options.Bytes
	if limit == 0 || s.source.options.Records == 0 {
		r.Unavailable = "inspection_limits_required"
		return nil
	}
	if s.source.span > limit || uint64(len(b)) > limit-s.source.span {
		r.Unavailable = "byte_limit"
		return nil
	}
	s.source.span += uint64(len(b))
	return bytes.Clone(b)
}
func (s *FileSigner) sourceStateBytes(r *Source, st state) []byte {
	if r == nil || r.Unavailable != "" {
		return nil
	}
	if uint64(len(st.records))+uint64(len(st.commits)) > s.source.options.Records {
		r.Unavailable = "record_limit"
		return nil
	}
	b, err := encodeState(st)
	if err != nil {
		r.Unavailable = "state_encoding"
		return nil
	}
	return s.sourceRetain(r, b)
}
func (s *FileSigner) sourceVoteRequest(r *Source, c *codec.Message, req VoteRequest) {
	if r == nil {
		return
	}
	r.RequestCode = uint64(c.Code)
	b, err := codec.EncodeMessage(c)
	if err != nil {
		r.Unavailable = "request_encoding"
		return
	}
	r.Request = s.sourceRetain(r, b)
	r.SealData = s.sourceRetain(r, req.SealData)
	if req.BadBlockReleased {
		r.BadBlockReleased = 1
	}
}
func (s *FileSigner) finishSourceLocked(r *Source, sig VoteSignature, err error) {
	if r == nil {
		return
	}
	r.After = s.sourceStateBytes(r, s.st)
	r.Signature = s.sourceRetain(r, sig.Signature)
	r.Seal = s.sourceRetain(r, sig.Seal)
	if sig.Reused {
		r.Reused = 1
	}
	switch {
	case err == nil:
		r.Result = "ok"
	case errors.Is(err, ErrBelowSignFloor):
		r.Result = "below_floor"
	case errors.Is(err, ErrDoubleSign):
		r.Result = "double_sign"
	case errors.Is(err, ErrSignStateNotEmpty):
		r.Result = "state_not_empty"
	case r.WriteResult == "failed":
		r.Result = "persist_error"
	default:
		r.Result = "other_error"
	}
	if r.Unavailable != "" {
		r.Before = nil
		r.After = nil
		r.Request = nil
		r.SealData = nil
		r.Signature = nil
		r.Seal = nil
		r.Write = nil
	}
	s.source.active = nil
}
func (s *FileSigner) publishSource(r *Source) {
	if r != nil {
		s.source.options.Observe(*r)
	}
}

// SignVoteWithSource returns the reference frozen inside the same original
// mutex operation. Reading a later "last sequence" would race other callers.
func (s *FileSigner) SignVoteWithSource(req VoteRequest) (VoteSignature, SourceRef, error) {
	return s.signVoteSource(req)
}
