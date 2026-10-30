package privval

import (
	"bytes"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func signerDomain(t *testing.T, activation uint64) *types.RoundChangeDomain {
	t.Helper()
	d, err := types.NewRoundChangeDomain(big.NewInt(7), types.Hash{1}, types.HeightFromUint64(activation))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDomainSignerNormalPersistenceReopenAndSourcePair(t *testing.T) {
	for _, activation := range []uint64{10, 11} {
		var observed []Source
		var expected []byte
		var signatures [][]byte
		for _, observing := range []bool{false, true} {
			store := fsys.NewMem()
			domain := signerDomain(t, activation)
			options := Options{FS: store, RoundChangeDomain: domain}
			if observing {
				options.Sources = &SourceOptions{Namespace: "normal-domain-signer", Records: 64, Bytes: 1 << 20,
					Observe: func(source Source) { observed = append(observed, source) }}
			}
			signer, err := NewKeySignerWithOptions(options, testKey(40), "/domain/state")
			if err != nil {
				t.Fatal(err)
			}
			initial, err := store.ReadFile("/domain/state")
			if err != nil || len(initial) == 0 || initial[0] != 2 || !signer.RoundChangeDomain().Equal(domain) {
				t.Fatal("fresh profile not durable before returning signer", err)
			}
			if err := signer.InitSignFloor(types.HeightFromUint64(0)); err != nil {
				t.Fatal(err)
			}
			if err := signer.ClearSignFloor(); err != nil {
				t.Fatal(err)
			}
			var got [][]byte
			proposal := preprepare(10, 0, 1)
			block := proposal.Msg.Proposal
			prepare := VoteRequest{Msg: &codec.Message{Code: codec.CodePrepare, View: view(10, 0), Digest: codec.BlockHash(block.Header)}, SealData: codec.SealData(block.Header, 0, types.PrepareSeal)}
			commit := VoteRequest{Msg: &codec.Message{Code: codec.CodeCommit, View: view(10, 0), Digest: codec.BlockHash(block.Header)}, SealData: codec.SealData(block.Header, 0, types.CommitSeal)}
			requests := []VoteRequest{proposal, prepare, commit, roundChange(10, 1, rp(0), 1)}
			for _, request := range requests {
				result, err := signer.SignVote(request)
				if err != nil {
					t.Fatal(err)
				}
				message := *request.Msg
				message.Seal = result.Seal
				payload, err := codec.SigningPayloadWithDomain(&message, domain)
				if err != nil || ecdsa.CheckSigner(payload, result.Signature, signer.Address()) != nil {
					t.Fatal("normal own-domain signing failed", err)
				}
				got = append(got, result.Signature)
				raw, err := store.ReadFile("/domain/state")
				if err != nil || raw[0] != 2 {
					t.Fatal("vote lost selected state envelope", err)
				}
			}
			signer, err = NewKeySignerWithOptions(options, testKey(40), "/domain/state")
			if err != nil {
				t.Fatal("ordinary selected reopen failed", err)
			}
			reused, err := signer.SignVote(requests[3])
			if err != nil || !reused.Reused || !bytes.Equal(reused.Signature, got[3]) {
				t.Fatal("reopen did not reuse own signature", err)
			}
			if _, err := signer.SignVote(roundChange(11, 1, nil, 0)); err != nil {
				t.Fatal("normal next-height signature failed", err)
			}
			raw, err := store.ReadFile("/domain/state")
			if err != nil || raw[0] != 2 {
				t.Fatal("selected file format changed at activation", err)
			}
			if _, err := decodeDomainState(raw, domain, signer.Address()); err != nil {
				t.Fatal("selected state did not retain canonical own records", err)
			}
			if observing {
				if !bytes.Equal(raw, expected) || len(got) != len(signatures) {
					t.Fatal("observation changed selected state")
				}
				for i := range got {
					if !bytes.Equal(got[i], signatures[i]) {
						t.Fatal("observation changed signature bytes")
					}
				}
			} else {
				expected, signatures = raw, got
			}
		}
		report, err := CheckSources(observed, SourceLimits{Lifetimes: 4, Operations: 64, Records: 128, Bytes: 16 << 20})
		if err != nil || report.Status != "consistent" || report.Lifetimes != 2 || report.Signed != 5 || report.Reused != 1 || report.Writes != 7 || report.PhysicalStatus != "unavailable" {
			t.Fatal("selected public-state transcript did not reconstruct", report, err)
		}
		for _, source := range observed {
			if source.Version != DomainSourceVersion || ValidateSource(source) != nil || source.Before[0] != 2 || source.After[0] != 2 || source.WriteAttempted == 1 && source.Write[0] != 2 {
				t.Fatal("selected observation lost profile framing")
			}
		}
	}
}

// This is an unsigned, read-only source model, not a failed physical writer.
type domainInspectionFS struct {
	fsys.FS
	raw    []byte
	err    error
	writes int
}

func (s *domainInspectionFS) ReadFile(string) ([]byte, error) { return s.raw, s.err }
func (s *domainInspectionFS) MkdirAll(string, fs.FileMode) error {
	s.writes++
	return errors.New("model: mutation forbidden")
}
func (s *domainInspectionFS) OpenFile(string, int, fs.FileMode) (fsys.File, error) {
	s.writes++
	return nil, errors.New("model: mutation forbidden")
}
func (s *domainInspectionFS) Rename(string, string) error {
	s.writes++
	return errors.New("model: mutation forbidden")
}
func (s *domainInspectionFS) Remove(string) error {
	s.writes++
	return errors.New("model: mutation forbidden")
}
func (s *domainInspectionFS) SyncDir(string) error {
	s.writes++
	return errors.New("model: mutation forbidden")
}

func TestDomainSignerUnsignedInspectionRefusesBeforeMutation(t *testing.T) {
	domain := signerDomain(t, 3)
	key, err := ecdsa.PrivateKeyFromBytes(testKey(41))
	if err != nil {
		t.Fatal(err)
	}
	self := ecdsa.Address(key)
	legacy, _ := encodeState(state{commits: map[string]types.Round{}})
	empty, _ := (&FileSigner{domain: domain, addr: self}).encodeState(state{commits: map[string]types.Round{}})
	for _, raw := range [][]byte{{}, legacy, {7}, {2, 0xc0}} {
		store := &domainInspectionFS{FS: fsys.NewMem(), raw: raw}
		if _, err := InspectSignState(store, "/model/state", self, domain); err == nil || store.writes != 0 {
			t.Fatal("invalid unsigned profile accepted or mutated")
		}
	}
	other, _ := types.NewRoundChangeDomain(big.NewInt(8), domain.GenesisHash(), domain.Activation())
	for _, candidate := range []*types.RoundChangeDomain{nil, new(types.RoundChangeDomain), other} {
		store := &domainInspectionFS{FS: fsys.NewMem(), raw: empty}
		if _, err := InspectSignState(store, "/model/state", self, candidate); err == nil || store.writes != 0 {
			t.Fatal("mismatched unsigned context accepted or mutated")
		}
	}
	store := &domainInspectionFS{FS: fsys.NewMem(), err: fsys.ErrNotExist}
	snapshot, err := InspectSignState(store, "/model/state", self, domain)
	if err != nil {
		t.Fatal(err)
	}
	// Change only a fresh unsigned model response, never a signed file or WAL.
	store.raw, store.err = empty, nil
	if _, err := snapshot.OpenKeySigner(testKey(41), nil, nil); !errors.Is(err, ErrStateProfile) || store.writes != 0 {
		t.Fatal("changed model source reached a mutation", err)
	}
	var zero StateSnapshot
	if _, err := zero.OpenKeySigner(testKey(41), nil, nil); !errors.Is(err, ErrStateProfile) {
		t.Fatal("zero snapshot granted a signer", err)
	}
	store = &domainInspectionFS{FS: fsys.NewMem(), err: os.ErrPermission}
	if _, err := InspectSignState(store, "/model/state", self, domain); !errors.Is(err, os.ErrPermission) || store.writes != 0 {
		t.Fatal("read error treated as fresh state", err)
	}
	store = &domainInspectionFS{FS: fsys.NewMem(), raw: empty}
	snapshot, err = InspectSignState(store, "/model/state", self, domain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.OpenKeySigner(testKey(49), nil, nil); !errors.Is(err, ErrStateProfile) || store.writes != 0 {
		t.Fatal("a different key materialized the inspected profile", err)
	}
}

func TestDomainSignerSnapshotSingleUseAndLegacyRefusal(t *testing.T) {
	store := fsys.NewMem()
	key, err := ecdsa.PrivateKeyFromBytes(testKey(42))
	if err != nil {
		t.Fatal(err)
	}
	domain := signerDomain(t, 3)
	snapshot, err := InspectSignState(store, "/selected/state", ecdsa.Address(key), domain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.OpenKeySigner(testKey(42), nil, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := store.ReadFile("/selected/state")
	if _, err := snapshot.OpenKeySigner(testKey(42), nil, nil); !errors.Is(err, ErrStateProfile) {
		t.Fatal("snapshot was reused", err)
	}
	if _, err := NewKeySigner(store, nil, testKey(42), "/selected/state"); !errors.Is(err, ErrStateFormat) {
		t.Fatal("legacy signer accepted selected state", err)
	}
	after, _ := store.ReadFile("/selected/state")
	if !bytes.Equal(before, after) {
		t.Fatal("refused reopen changed original state")
	}
	// Inspect a deliberately unsigned state with an empty signature record.
	wire := domainStateRLP{1, big.NewInt(7), domain.GenesisHash(), big.NewInt(3), ecdsa.Address(key), nil}
	st := state{highest: new(types.Height), commits: map[string]types.Round{}, records: []record{{code: codec.CodeRoundChange}}}
	wire.State, _ = encodeState(st)
	body, _ := rlp.Encode(wire)
	model := &domainInspectionFS{FS: fsys.NewMem(), raw: append([]byte{2}, body...)}
	if _, err := InspectSignState(model, "/model/state", ecdsa.Address(key), domain); !errors.Is(err, ErrStateCorrupt) || model.writes != 0 {
		t.Fatal("unsigned record granted an owner", err)
	}
}

func TestDomainSignerNormalObserverCanInspectConsumedSnapshot(t *testing.T) {
	store := fsys.NewMem()
	key, err := ecdsa.PrivateKeyFromBytes(testKey(45))
	if err != nil {
		t.Fatal(err)
	}
	domain := signerDomain(t, 3)
	snapshot, err := InspectSignState(store, "/callback/state", ecdsa.Address(key), domain)
	if err != nil {
		t.Fatal(err)
	}
	observations := 0
	observer := &SourceOptions{Namespace: "normal-domain-callback", Records: 16, Bytes: 1 << 20,
		Observe: func(source Source) {
			observations++
			if ValidateSource(source) != nil {
				t.Error("normal initial source is malformed")
			}
			// Reentrant metadata inspection must refuse the consumed capability
			// immediately, with no second writer or callback recursion.
			if _, err := snapshot.OpenKeySigner(testKey(45), nil, nil); !errors.Is(err, ErrStateProfile) {
				t.Error("observer reused the consumed snapshot", err)
			}
		}}
	signer, err := snapshot.OpenKeySigner(testKey(45), nil, observer)
	if err != nil || observations != 1 || signer == nil || !signer.Empty() {
		t.Fatal("normal reentrant observation did not complete", observations, err)
	}
}

func TestDomainSignerUnsignedSnapshotCopiesShareOneClaim(t *testing.T) {
	domain := signerDomain(t, 3)
	key, err := ecdsa.PrivateKeyFromBytes(testKey(46))
	if err != nil {
		t.Fatal(err)
	}
	self := ecdsa.Address(key)
	raw, err := (&FileSigner{domain: domain, addr: self}).encodeState(state{commits: map[string]types.Round{}})
	if err != nil {
		t.Fatal(err)
	}
	// An existing unsigned profile model performs no persistence or signing.
	// Fresh-absence behavior alone would not detect copied one-use wrappers.
	store := &domainInspectionFS{FS: fsys.NewMem(), raw: raw}
	snapshot, err := InspectSignState(store, "/model/state", self, domain)
	if err != nil {
		t.Fatal(err)
	}
	first, second := *snapshot, *snapshot
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []*StateSnapshot{&first, &second} {
		go func(capability *StateSnapshot) {
			<-start
			_, err := capability.OpenKeySigner(testKey(46), nil, nil)
			results <- err
		}(candidate)
	}
	close(start)
	success, refused := 0, 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			success++
		} else if errors.Is(err, ErrStateProfile) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || refused != 1 || store.writes != 0 || !bytes.Equal(raw, store.raw) {
		t.Fatal("copied wrappers bypassed the shared one-use claim", success, refused, store.writes)
	}
}
