package privval

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/faultpoint"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

const domainStateFormat byte = 2
const domainStateVersion uint64 = 1

var _ DomainSigner = (*FileSigner)(nil)

// ErrStateProfile reports an incompatible or changed domain-bound state.
var ErrStateProfile = errors.New("privval: incompatible sign state profile")

type domainStateRLP struct {
	Version    uint64
	ChainID    *big.Int
	Genesis    types.Hash
	Activation *big.Int
	Self       types.Address
	State      []byte
}

// StateSnapshot is a single-use read-only inspection result. Its private
// source is not forgeable by setting exported fields. It grants no physical
// durability or protection against an external concurrent filesystem writer.
type StateSnapshot struct {
	src *domainStateSource
}

type domainStateSource struct {
	mu     sync.Mutex
	used   bool
	fs     fsys.FS
	file   string
	self   types.Address
	domain *types.RoundChangeDomain
	exists bool
	raw    []byte
	state  state
}

// InspectSignState reads a selected state without creating directories, files
// or observations. Only an absent state is fresh; a legacy file is not migrated.
func InspectSignState(fs fsys.FS, file string, self types.Address, domain *types.RoundChangeDomain) (*StateSnapshot, error) {
	if fs == nil {
		fs = fsys.OS{}
	}
	if domain == nil || domain.Validate() != nil || self == (types.Address{}) || file == "" {
		return nil, ErrStateProfile
	}
	source := &domainStateSource{fs: fs, file: file, self: self, domain: domain.Copy(), state: state{commits: map[string]types.Round{}}}
	raw, err := fs.ReadFile(file)
	if fsys.IsNotExist(err) {
		return &StateSnapshot{src: source}, nil
	}
	if err != nil {
		return nil, err
	}
	source.raw, source.exists = bytes.Clone(raw), true
	source.state, err = decodeDomainState(source.raw, source.domain, self)
	if err != nil {
		return nil, err
	}
	return &StateSnapshot{src: source}, nil
}

// OpenKeySigner rechecks the same source and key before the first mutation.
// A fresh empty profile is durable before a signer can return any signature.
func (snapshot *StateSnapshot) OpenKeySigner(secret []byte, faults faultpoint.Handler, sources *SourceOptions) (*FileSigner, error) {
	if snapshot == nil || snapshot.src == nil {
		return nil, ErrStateProfile
	}
	material, err := newSignerMaterial(snapshot.src.fs, faults, secret, snapshot.src.file)
	if err != nil {
		return nil, err
	}
	return snapshot.openMaterial(material, sources)
}

func (snapshot *StateSnapshot) openMaterial(signer *FileSigner, sources *SourceOptions) (*FileSigner, error) {
	source, err := snapshot.claimSource(signer.addr)
	if err != nil {
		return nil, err
	}
	// Filesystem hooks and observers may reenter public methods. The consumed
	// capability rejects reuse without holding its mutex across any such call.
	raw, err := source.fs.ReadFile(source.file)
	if err != nil && !fsys.IsNotExist(err) {
		return nil, err
	}
	if (err == nil) != source.exists || err == nil && !bytes.Equal(raw, source.raw) {
		return nil, ErrStateProfile
	}
	signer.domain, signer.st = source.domain.Copy(), source.state.clone()
	if !source.exists {
		if err := source.fs.MkdirAll(filepath.Dir(source.file), 0o700); err != nil {
			return nil, err
		}
		if err := signer.commit(signer.st); err != nil {
			return nil, err
		}
	}
	signer.initializeSource(sources)
	return signer, nil
}

func (snapshot *StateSnapshot) claimSource(self types.Address) (*domainStateSource, error) {
	if snapshot == nil || snapshot.src == nil {
		return nil, ErrStateProfile
	}
	source := snapshot.src
	// Copies of the exported wrapper share this private one-use claim.
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.used || self != source.self {
		return nil, ErrStateProfile
	}
	source.used = true
	return source, nil
}

func newDomainSigner(options Options, secret []byte, file string) (*FileSigner, error) {
	if options.RoundChangeDomain.Validate() != nil || options.RoundChangeDomain == nil {
		return nil, ErrStateProfile
	}
	fs := options.FS
	if fs == nil {
		fs = fsys.OS{}
	}
	signer, err := newSignerMaterial(fs, options.Faults, secret, file)
	if err != nil {
		return nil, err
	}
	snapshot, err := InspectSignState(fs, file, signer.addr, options.RoundChangeDomain)
	if err != nil {
		return nil, err
	}
	return snapshot.openMaterial(signer, options.Sources)
}

// RoundChangeDomain returns independent context storage. Nil is legacy-only.
func (s *FileSigner) RoundChangeDomain() *types.RoundChangeDomain { return s.domain.Copy() }

func (s *FileSigner) encodeState(st state) ([]byte, error) {
	legacy, err := encodeState(st)
	if err != nil || s.domain == nil {
		return legacy, err
	}
	body, err := rlp.Encode(domainStateRLP{domainStateVersion, s.domain.ChainID(), s.domain.GenesisHash(), s.domain.Activation().Big(), s.addr, legacy})
	if err != nil {
		return nil, err
	}
	return append([]byte{domainStateFormat}, body...), nil
}

func decodeDomainState(raw []byte, domain *types.RoundChangeDomain, self types.Address) (state, error) {
	var empty state
	if len(raw) == 0 {
		return empty, ErrStateCorrupt
	}
	if raw[0] == stateFormat {
		return empty, ErrStateProfile
	}
	if raw[0] != domainStateFormat {
		return empty, ErrStateFormat
	}
	var wire domainStateRLP
	if rlp.DecodeStrict(raw[1:], &wire) != nil {
		return empty, ErrStateCorrupt
	}
	if wire.Version != domainStateVersion {
		return empty, ErrStateFormat
	}
	if wire.ChainID == nil || wire.Activation == nil || wire.ChainID.Cmp(domain.ChainID()) != 0 || wire.Genesis != domain.GenesisHash() || wire.Activation.Cmp(domain.Activation().Big()) != 0 || wire.Self != self {
		return empty, ErrStateProfile
	}
	st, err := decodeState(wire.State)
	if err != nil {
		return empty, err
	}
	seen := map[string]bool{}
	for _, record := range st.records {
		key := fmt.Sprintf("%d/%s/%s", record.code, record.seq.String(), record.round.String())
		if seen[key] || st.highest == nil || record.seq.Cmp(*st.highest) > 0 || record.code < codec.CodePreprepare || record.code > codec.CodeRoundChange {
			return empty, ErrStateCorrupt
		}
		seen[key] = true
		owner, err := ecdsa.RecoverAddress(record.payload, record.signature)
		if err != nil || owner != self {
			return empty, ErrStateCorrupt
		}
	}
	for sequence := range st.commits { //wbft:unordered independent validation
		h, ok := new(big.Int).SetString(sequence, 10)
		if !ok || st.highest == nil || h.Cmp(st.highest.Big()) > 0 {
			return empty, ErrStateCorrupt
		}
	}
	canonical, err := (&FileSigner{domain: domain, addr: self}).encodeState(st)
	if err != nil || !bytes.Equal(canonical, raw) {
		return empty, ErrStateCorrupt
	}
	return st, nil
}
