package privval

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// Signer signs the node's consensus messages and randao reveals. A remote
// signer implements the same interface and keeps the same rules on its side.
type Signer interface {
	// Address is the address of the node key.
	Address() types.Address
	// BLSPublicKey is the compressed BLS public key derived from the node
	// key.
	BLSPublicKey() []byte
	// SignVote signs a consensus message; for PREPARE and COMMIT it also
	// returns the BLS seal over the seal data. It persists the sign state
	// before it returns.
	SignVote(req VoteRequest) (VoteSignature, error)
	// SignRandao returns ecdsa_sign(key, randao_data(chainID, number)),
	// deterministic and with a low S. number is the full block number.
	SignRandao(chainID *big.Int, number types.Height) ([]byte, error)
}

// VoteRequest is one message to sign.
type VoteRequest struct {
	// Msg is the unsigned message of the core. Its Seal and Signature are
	// ignored.
	Msg *codec.Message
	// SealData is seal_data(header, round, type) for PREPARE and COMMIT.
	SealData []byte
	// BadBlockReleased states that the bad-block rule of the core released
	// the prepared pair of this ROUND-CHANGE's sequence
	// (consensus.Broadcast.BadBlockReleased). It is honoured only for a
	// ROUND-CHANGE without a prepared pair.
	BadBlockReleased bool
}

// VoteSignature is the result of SignVote.
type VoteSignature struct {
	Signature []byte
	Seal      []byte // PREPARE, COMMIT
	Reused    bool   // the stored signature was returned
}

// Refusals and state errors.
var (
	ErrDoubleSign        = errors.New("privval: refused, would double sign")
	ErrBelowSignFloor    = errors.New("privval: refused, at or below the sign floor")
	ErrSignStateNotEmpty = errors.New("privval: sign state already holds a signature")
	ErrStateCorrupt      = errors.New("privval: sign state file is damaged")
	ErrStateFormat       = errors.New("privval: sign state file has an unknown format")
	ErrBadRequest        = errors.New("privval: malformed sign request")
)

// IsRefusal reports whether err is a refusal of the sign rules (as opposed
// to a failure to read or write the sign state).
func IsRefusal(err error) bool {
	return errors.Is(err, ErrDoubleSign) || errors.Is(err, ErrBelowSignFloor)
}

// stateFormat is the first byte of the sign state file.
const stateFormat = 1

// record is one signature of the sign state.
type record struct {
	code      codec.Code
	seq       types.Height
	round     types.Round
	payload   types.Hash // keccak256 of the signing payload (seal included)
	signature []byte
	seal      []byte
	prepared  *types.Round // ROUND-CHANGE only
}

// state is the last-sign state: the signatures of the highest recorded
// height and the height below it, the highest recorded height, the highest
// COMMIT round per kept height and the sign floor.
type state struct {
	highest *types.Height
	floor   *types.Height
	records []record
	commits map[string]types.Round // key: seq.String()
}

// Options configure a FileSigner.
type Options struct {
	// FS is the file system of the state file; nil means the operating
	// system.
	FS fsys.FS
	// Faults is called at the fault points of the sign state write.
	Faults faultpoint.Handler
}

// FileSigner signs with a node key file and keeps its sign state in a file.
// It is safe for concurrent use.
type FileSigner struct {
	mu     sync.Mutex // privval.signer.mu
	fs     fsys.FS
	file   string
	dir    string
	faults faultpoint.Handler

	key    *ecdsa.PrivateKey
	bls    *bls.SecretKey
	addr   types.Address
	blsPub []byte

	st state
}

var _ Signer = (*FileSigner)(nil)

// NewFileSigner reads keyFile in the go-stablenet nodekey format and the
// sign state in stateFile (absent: an empty state). The BLS secret key is
// derived from the node key, not stored. A damaged state file is an error:
// the node must not start without its sign record.
func NewFileSigner(keyFile, stateFile string) (*FileSigner, error) {
	return OpenFileSigner(Options{}, keyFile, stateFile)
}

// OpenFileSigner is NewFileSigner with options.
func OpenFileSigner(opt Options, keyFile, stateFile string) (*FileSigner, error) {
	fs := opt.FS
	if fs == nil {
		fs = fsys.OS{}
	}
	raw, err := fs.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	secret, err := ParseKeyFile(raw)
	if err != nil {
		return nil, err
	}
	return newSigner(fs, opt.Faults, secret, stateFile)
}

// NewKeySigner returns a signer for the 32-byte secret key with its sign state
// in stateFile on fs. Tests and simulations use it with test keys.
func NewKeySigner(fs fsys.FS, faults faultpoint.Handler, secret []byte, stateFile string) (*FileSigner, error) {
	return newSigner(fs, faults, secret, stateFile)
}

func newSigner(fs fsys.FS, faults faultpoint.Handler, secret []byte, stateFile string) (*FileSigner, error) {
	key, err := ecdsa.PrivateKeyFromBytes(secret)
	if err != nil {
		return nil, err
	}
	bk, err := bls.DeriveSecretKey(secret)
	if err != nil {
		return nil, err
	}
	s := &FileSigner{
		fs: fs, file: stateFile, dir: filepath.Dir(stateFile), faults: faults,
		key: key, bls: bk, addr: ecdsa.Address(key), blsPub: bk.PublicKey().Bytes(),
		st: state{commits: map[string]types.Round{}},
	}
	data, err := fs.ReadFile(stateFile)
	switch {
	case fsys.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		st, err := decodeState(data)
		if err != nil {
			return nil, err
		}
		s.st = st
	}
	return s, nil
}

// Address implements Signer.
func (s *FileSigner) Address() types.Address { return s.addr }

// BLSPublicKey implements Signer.
func (s *FileSigner) BLSPublicKey() []byte { return bytes.Clone(s.blsPub) }

// SignRandao implements Signer. The sign floor does not apply: the reveal is
// deterministic.
func (s *FileSigner) SignRandao(chainID *big.Int, number types.Height) ([]byte, error) {
	return ecdsa.SignData(codec.RandaoData(chainID, number), s.key)
}

// Empty reports that the sign state holds no signature record and no floor:
// the state file was absent, or it exists but nothing was recorded in it.
func (s *FileSigner) Empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.highest == nil && s.st.floor == nil && len(s.st.records) == 0
}

// InitSignFloor records "sign nothing at height <= h". It is allowed only
// while no signature has been recorded (otherwise ErrSignStateNotEmpty); the
// floor is durable when it returns.
func (s *FileSigner) InitSignFloor(h types.Height) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.highest != nil {
		return ErrSignStateNotEmpty
	}
	next := s.st.clone()
	next.floor = &h
	return s.commit(next)
}

// ClearSignFloor removes the floor. It is allowed only while no signature has
// been recorded.
func (s *FileSigner) ClearSignFloor() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.highest != nil {
		return ErrSignStateNotEmpty
	}
	next := s.st.clone()
	next.floor = nil
	return s.commit(next)
}

// SignFloor returns the floor and true if one is set.
func (s *FileSigner) SignFloor() (types.Height, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.floor == nil {
		return types.Height{}, false
	}
	return *s.st.floor, true
}

// LastHeight returns the greater of the highest signed height and the sign
// floor (H_sign of the start-up handshake), and false when there is neither.
func (s *FileSigner) LastHeight() (types.Height, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.st.highest == nil && s.st.floor == nil:
		return types.Height{}, false
	case s.st.highest == nil:
		return *s.st.floor, true
	case s.st.floor == nil || s.st.highest.Cmp(*s.st.floor) >= 0:
		return *s.st.highest, true
	}
	return *s.st.floor, true
}

// preparedRank orders prepared rounds with "none" below every round.
func preparedRank(a, b *types.Round) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return a.Cmp(*b)
}

// SignVote implements Signer. The rules, per message kind and view
// (sequence, round):
//
//   - at or below the sign floor every kind is refused (ErrBelowSignFloor);
//   - below the highest recorded height only the re-signing of the same
//     payload is allowed;
//   - PRE-PREPARE, PREPARE and COMMIT: the same payload returns the stored
//     signature, a different one is refused;
//   - ROUND-CHANGE: the same payload returns the stored signature; a
//     different one is signed and replaces the stored one when its prepared
//     round is not below the stored one, and refused otherwise; after a
//     COMMIT of round r at the sequence, a ROUND-CHANGE of that sequence
//     must report a prepared round of at least r. Both conditions are
//     waived for a ROUND-CHANGE without a prepared pair whose request says
//     that the bad-block rule released the pair (BadBlockReleased).
//
// Heights are compared with their full values.
func (s *FileSigner) SignVote(req VoteRequest) (VoteSignature, error) {
	m := req.Msg
	if m == nil {
		return VoteSignature{}, ErrBadRequest
	}
	switch m.Code {
	case codec.CodePreprepare, codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange:
	default:
		return VoteSignature{}, ErrBadRequest
	}
	c := *m
	c.Signature = nil
	c.Seal = nil
	if m.Code == codec.CodePrepare || m.Code == codec.CodeCommit {
		if len(req.SealData) == 0 {
			return VoteSignature{}, ErrBadRequest
		}
		c.Seal = s.bls.Sign(req.SealData).Bytes()
	}
	payload, err := codec.SigningPayload(&c, false, nil)
	if err != nil {
		return VoteSignature{}, err
	}
	ph := keccak.Sum256(payload)
	seq, round := m.View.Sequence, m.View.Round

	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	if st.floor != nil && seq.Cmp(*st.floor) <= 0 {
		return VoteSignature{}, ErrBelowSignFloor
	}
	old := st.find(m.Code, seq, round)
	if old != nil && old.payload == ph {
		return VoteSignature{Signature: bytes.Clone(old.signature), Seal: bytes.Clone(old.seal), Reused: true}, nil
	}
	if st.highest != nil && seq.Cmp(*st.highest) < 0 {
		return VoteSignature{}, fmt.Errorf("%w: height %s below the highest signed height %s", ErrDoubleSign, seq, st.highest)
	}
	var prepared *types.Round
	if m.Code == codec.CodeRoundChange {
		prepared = m.PreparedRound
		released := req.BadBlockReleased && prepared == nil
		if cr, ok := st.commits[seq.String()]; ok && !released && (prepared == nil || prepared.Cmp(cr) < 0) {
			return VoteSignature{}, fmt.Errorf("%w: ROUND-CHANGE below the COMMIT of round %s", ErrDoubleSign, cr)
		}
		if old != nil && !released && preparedRank(prepared, old.prepared) < 0 {
			return VoteSignature{}, fmt.Errorf("%w: ROUND-CHANGE with a lower prepared round", ErrDoubleSign)
		}
	} else if old != nil {
		return VoteSignature{}, fmt.Errorf("%w: code %d at view (%s, %s)", ErrDoubleSign, m.Code, seq, round)
	}
	sig, err := ecdsa.Sign(ph, s.key)
	if err != nil {
		return VoteSignature{}, err
	}
	next := st.clone()
	next.put(record{code: m.Code, seq: seq, round: round, payload: ph, signature: sig, seal: c.Seal, prepared: prepared})
	if m.Code == codec.CodeCommit {
		if cr, ok := next.commits[seq.String()]; !ok || round.Cmp(cr) > 0 {
			next.commits[seq.String()] = round
		}
	}
	if next.highest == nil || seq.Cmp(*next.highest) > 0 {
		h := seq
		next.highest = &h
	}
	next.prune()
	if err := s.commit(next); err != nil {
		return VoteSignature{}, err
	}
	return VoteSignature{Signature: bytes.Clone(sig), Seal: bytes.Clone(c.Seal)}, nil
}

// commit writes next durably and then makes it the state.
func (s *FileSigner) commit(next state) error {
	data, err := encodeState(next)
	if err != nil {
		return err
	}
	faultpoint.Hit(s.faults, faultpoint.PrivvalBeforePersist)
	if err := fsys.WriteFileAtomic(s.fs, s.dir, s.file, data, 0o600); err != nil {
		return err
	}
	faultpoint.Hit(s.faults, faultpoint.PrivvalAfterPersist)
	s.st = next
	return nil
}

func (st *state) find(code codec.Code, seq types.Height, round types.Round) *record {
	for i := range st.records {
		r := &st.records[i]
		if r.code == code && r.seq.Cmp(seq) == 0 && r.round.Cmp(round) == 0 {
			return r
		}
	}
	return nil
}

func (st *state) put(r record) {
	for i := range st.records {
		o := &st.records[i]
		if o.code == r.code && o.seq.Cmp(r.seq) == 0 && o.round.Cmp(r.round) == 0 {
			*o = r
			return
		}
	}
	st.records = append(st.records, r)
}

// prune keeps the records and COMMIT rounds of the highest height and the
// height below it.
func (st *state) prune() {
	if st.highest == nil {
		return
	}
	keep := func(seq types.Height) bool {
		d, ok := st.highest.Sub(seq)
		return !ok || d.CmpUint64(1) <= 0
	}
	st.records = slices.DeleteFunc(st.records, func(r record) bool { return !keep(r.seq) })
	for k := range st.commits { //wbft:unordered deletion only
		h, ok := new(big.Int).SetString(k, 10)
		if ok && !keep(types.MustHeightFromBig(h)) {
			delete(st.commits, k)
		}
	}
}

func (st *state) clone() state {
	c := state{highest: st.highest, floor: st.floor, records: slices.Clone(st.records), commits: make(map[string]types.Round, len(st.commits))}
	for k, v := range st.commits { //wbft:unordered copy
		c.commits[k] = v
	}
	return c
}

// File encoding: one format byte, then the RLP list of fileState.

type fileRecord struct {
	Code        uint64
	Seq         *big.Int
	Round       *big.Int
	Payload     types.Hash
	Signature   []byte
	Seal        []byte
	HasPrepared uint64
	Prepared    *big.Int
}

type fileCommit struct {
	Seq   *big.Int
	Round *big.Int
}

type fileState struct {
	HasHighest uint64
	Highest    *big.Int
	HasFloor   uint64
	Floor      *big.Int
	Records    []fileRecord
	Commits    []fileCommit
}

func encodeState(st state) ([]byte, error) {
	var f fileState
	f.Highest, f.Floor = new(big.Int), new(big.Int)
	if st.highest != nil {
		f.HasHighest, f.Highest = 1, st.highest.Big()
	}
	if st.floor != nil {
		f.HasFloor, f.Floor = 1, st.floor.Big()
	}
	recs := slices.Clone(st.records)
	slices.SortStableFunc(recs, func(a, b record) int {
		if c := a.seq.Cmp(b.seq); c != 0 {
			return c
		}
		if c := a.round.Cmp(b.round); c != 0 {
			return c
		}
		return int(a.code) - int(b.code)
	})
	for _, r := range recs {
		fr := fileRecord{Code: uint64(r.code), Seq: r.seq.Big(), Round: r.round.Big(), Payload: r.payload,
			Signature: r.signature, Seal: r.seal, Prepared: new(big.Int)}
		if fr.Seal == nil {
			fr.Seal = []byte{}
		}
		if r.prepared != nil {
			fr.HasPrepared, fr.Prepared = 1, r.prepared.Big()
		}
		f.Records = append(f.Records, fr)
	}
	keys := make([]string, 0, len(st.commits))
	for k := range st.commits { //wbft:unordered the keys are sorted below
		keys = append(keys, k)
	}
	slices.SortStableFunc(keys, func(a, b string) int {
		x, _ := new(big.Int).SetString(a, 10)
		y, _ := new(big.Int).SetString(b, 10)
		return x.Cmp(y)
	})
	for _, k := range keys {
		h, _ := new(big.Int).SetString(k, 10)
		f.Commits = append(f.Commits, fileCommit{Seq: h, Round: st.commits[k].Big()})
	}
	body, err := rlp.Encode(&f)
	if err != nil {
		return nil, err
	}
	return append([]byte{stateFormat}, body...), nil
}

func decodeState(data []byte) (state, error) {
	st := state{commits: map[string]types.Round{}}
	if len(data) == 0 {
		return st, ErrStateCorrupt
	}
	if data[0] != stateFormat {
		return st, fmt.Errorf("%w: %d", ErrStateFormat, data[0])
	}
	var f fileState
	if err := rlp.DecodeStrict(data[1:], &f); err != nil {
		return st, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	bigH := func(b *big.Int) (types.Height, error) {
		if b == nil {
			return types.HeightFromUint64(0), nil
		}
		return types.HeightFromBig(b)
	}
	bigR := func(b *big.Int) (types.Round, error) {
		if b == nil {
			return types.RoundFromUint64(0), nil
		}
		return types.RoundFromBig(b)
	}
	if f.HasHighest > 1 || f.HasFloor > 1 {
		return st, ErrStateCorrupt
	}
	if f.HasHighest == 1 {
		h, err := bigH(f.Highest)
		if err != nil {
			return st, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
		}
		st.highest = &h
	}
	if f.HasFloor == 1 {
		h, err := bigH(f.Floor)
		if err != nil {
			return st, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
		}
		st.floor = &h
	}
	for _, fr := range f.Records {
		seq, err1 := bigH(fr.Seq)
		round, err2 := bigR(fr.Round)
		if err1 != nil || err2 != nil || fr.HasPrepared > 1 {
			return st, ErrStateCorrupt
		}
		r := record{code: codec.Code(fr.Code), seq: seq, round: round, payload: fr.Payload, signature: fr.Signature, seal: fr.Seal}
		if len(r.seal) == 0 {
			r.seal = nil
		}
		if fr.HasPrepared == 1 {
			p, err := bigR(fr.Prepared)
			if err != nil {
				return st, ErrStateCorrupt
			}
			r.prepared = &p
		}
		st.records = append(st.records, r)
	}
	for _, c := range f.Commits {
		h, err1 := bigH(c.Seq)
		r, err2 := bigR(c.Round)
		if err1 != nil || err2 != nil {
			return st, ErrStateCorrupt
		}
		st.commits[h.String()] = r
	}
	if (len(st.records) > 0 || len(st.commits) > 0) && st.highest == nil {
		return st, ErrStateCorrupt
	}
	return st, nil
}
