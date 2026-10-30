package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// All alternate records below are fresh unsigned metadata models. No runtime
// journal, signer state, signed payload, or existing source is modified.
func profileEncoding(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := rlp.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func profileHeader(t *testing.T, activation uint64) wal.Record {
	t.Helper()
	fs := fsys.NewMem()
	id := journal.Identity{Run: "profile-model"}
	if activation != 0 {
		id.ChainID, id.GenesisHash = big.NewInt(7), types.Hash{1}
		id.Core.ChainConfig = []byte(fmt.Sprintf(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":%d}}}`, activation))
		cfg, err := types.ParseChainConfig(id.Core.ChainConfig)
		if err != nil {
			t.Fatal(err)
		}
		domain, err := types.DomainForConfig(cfg, id.GenesisHash)
		if err != nil {
			t.Fatal(err)
		}
		id.Core.DomainBytes, err = codec.EncodeRoundChangeDomain(domain)
		if err != nil {
			t.Fatal(err)
		}
	}
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/header", Synchronous: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := wal.OpenReader(fs, "/header", wal.Position{})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func profileFixture(t *testing.T, records ...wal.Record) *fsys.Mem {
	t.Helper()
	fs := fsys.NewMem()
	w, _, err := wal.Open(fs, "/j", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if _, err := w.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return fs
}

func profileSigner(t *testing.T, version uint64) wal.Record {
	t.Helper()
	raw := profileEncoding(t, struct {
		Format, JSeq uint64
		Source       journal.SignerRec
	}{journal.Format, 2, journal.SignerRec{Source: privval.Source{Version: version}}})
	return wal.Record{Format: journal.Format, Kind: uint8(journal.KindSigner), Body: raw}
}

func profileFutureCore(t *testing.T) wal.Record {
	return profileCore(t, nil, true)
}

func profileCore(t *testing.T, domain []byte, future bool) wal.Record {
	t.Helper()
	fs := fsys.NewMem()
	w, err := journal.Open(journal.Options{FS: fs, Dir: "/core", Synchronous: true}, journal.Identity{Run: "profile-model"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := inputlog.Encode(consensus.Start{})
	if err != nil {
		t.Fatal(err)
	}
	outs, err := inputlog.EncodeOutputs(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := inputlog.OutDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Put(journal.Record{Body: &journal.CoreStepRec{DomainBytes: domain, EngineRun: 1, Step: 1, Via: "engine", InputKind: inputlog.KindStart, Input: in, Outputs: outs, OutDigest: digest}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := wal.OpenReader(fs, "/core", wal.Position{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	record, _, err := r.Next()
	if err != nil || record.Kind != uint8(journal.KindCoreStep) {
		t.Fatal("missing model core source", err)
	}
	if !future {
		return record
	}
	fields, err := rlp.ListItems(record.Body)
	if err != nil {
		t.Fatal(err)
	}
	fields[5] = profileEncoding(t, uint64(3))
	return wal.Record{Format: journal.Format, Kind: record.Kind, Body: profileEncoding(t, fields)}
}

func TestDomainProfileR01DetachedSelectedRecords(t *testing.T) {
	domain, err := types.NewRoundChangeDomain(big.NewInt(7), types.Hash{1}, types.HeightFromUint64(3))
	if err != nil {
		t.Fatal(err)
	}
	description, err := codec.EncodeRoundChangeDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	source := privval.Source{Version: 2, Action: "initial", Result: "ok", Unavailable: "namespace_missing", DomainBytes: description}
	if err := privval.ValidateSource(source); err != nil {
		t.Fatal(err)
	}
	makeSigner := func(source privval.Source) wal.Record {
		return wal.Record{Format: journal.Format, Kind: uint8(journal.KindSigner), Body: profileEncoding(t, struct {
			Format, JSeq uint64
			Source       journal.SignerRec
		}{journal.Format, 2, journal.SignerRec{Source: source}})}
	}
	marker := source
	marker.DomainBytes, marker.Unavailable = nil, "domain_declaration_unavailable"
	for i, record := range []wal.Record{makeSigner(source), makeSigner(marker), profileCore(t, description, false)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			fs := profileFixture(t, profileHeader(t, 0), record)
			reader, err := journal.OpenReader(fs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Next(); err != nil {
				t.Fatal(err)
			}
			decoded, err := reader.Next()
			if err != nil {
				t.Fatal("selected model is not readable", err)
			}
			for _, from := range []string{"", "999999999"} {
				if _, err := exportR01(fs, "/j", "/out", from, ""); !errors.Is(err, journal.ErrDomainSourceUnsupported) {
					t.Fatal("selected record fell back", err)
				}
				if _, err := fs.ReadDir("/out"); !fsys.IsNotExist(err) {
					t.Fatal("selected record created output", err)
				}
			}
			w := &r01Writer{}
			w.indexOwnInputs(fs, "/j")
			if !errors.Is(w.profileErr, journal.ErrDomainSourceUnsupported) {
				t.Fatal("index missed selected record", w.profileErr)
			}
			if err := w.record(decoded, wal.Position{}); !errors.Is(err, journal.ErrDomainSourceUnsupported) {
				t.Fatal("output missed selected record", err)
			}
		})
	}
}

func profileCommandArgs(t *testing.T, fs fsys.FS, command string) []string {
	t.Helper()
	args := []string{command, "--dir", "/j"}
	switch command {
	case "check-write-cache", "check-receive-cache", "check-write-io":
		args = append(args, "--max-records", "100", "--max-ledgers", "8", "--max-reordered", "8")
		if command == "check-write-io" {
			args = append(args, "--max-sessions", "8", "--max-requests", "8", "--max-frames", "100")
		}
	case "check-round-change-retry", "check-receive-failures":
		var limits any = retryCommandLimits()
		if command == "check-receive-failures" {
			limits = failureCommandLimits()
		}
		raw, err := json.Marshal(limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := fsys.WriteFileAtomic(fs, "/", "/limits.json", raw, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--source-limits", "/limits.json")
	}
	return args
}

func TestDomainProfileCLIUnsupportedAndMalformed(t *testing.T) {
	header := profileHeader(t, 0)
	commands := []string{"check-write-cache", "check-receive-cache", "check-write-io", "check-round-change-retry", "check-receive-failures", "verify", "stat"}
	for _, model := range []struct {
		name        string
		record      wal.Record
		unsupported bool
	}{
		{"future-signer", profileSigner(t, 3), true},
		{"future-core", profileFutureCore(t), true},
		{"malformed-source2", profileSigner(t, 2), false},
	} {
		for _, command := range commands {
			t.Run(model.name+"/"+command, func(t *testing.T) {
				fs := profileFixture(t, header, model.record)
				args := profileCommandArgs(t, fs, command)
				if model.unsupported {
					var result map[string]any
					runJSON(t, fs, 69, &result, args...)
					if result["status"] != "unavailable" || result["reason"] != "unsupported_source_profile" || result["physical_status"] != "unavailable" {
						t.Fatal(result)
					}
					if command == "check-receive-failures" && result["schedule_status"] != "unavailable" {
						t.Fatal(result)
					}
				} else if command == "verify" {
					var result verifyResult
					runJSON(t, fs, 1, &result, args...)
					if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], "reading stopped") {
						t.Fatal(result)
					}
				} else if command == "stat" {
					var result statResult
					runJSON(t, fs, 0, &result, args...)
					if !strings.Contains(result.End, "malformed record") {
						t.Fatal(result)
					}
				} else {
					runJSON(t, fs, 2, nil, args...)
				}
			})
		}
	}
	for _, command := range commands {
		fs := fsys.NewMem()
		args := profileCommandArgs(t, fs, command)
		runJSON(t, profileReadErrorFS{FS: fs}, 2, nil, args...)
	}
}

type profileReadErrorFS struct{ fsys.FS }

func (fs profileReadErrorFS) ReadDir(string) ([]string, error) {
	return nil, errors.New("model directory read unavailable")
}

func TestDomainProfileVerifyPreservesEarlierContradiction(t *testing.T) {
	header := profileHeader(t, 0)
	fields, err := rlp.ListItems(header.Body)
	if err != nil {
		t.Fatal(err)
	}
	fields[1] = profileEncoding(t, uint64(3))
	duplicate := wal.Record{Format: journal.Format, Kind: header.Kind, Body: profileEncoding(t, fields)}
	fs := profileFixture(t, header, duplicate, profileSigner(t, 3))
	var result verifyResult
	runJSON(t, fs, 1, &result, "verify", "--dir", "/j")
	if len(result.Problems) != 1 || !strings.Contains(result.Problems[0], "jseq 3, want 2") {
		t.Fatal(result)
	}
}

func TestDomainProfileR01RefusalBeforeRecoveryAndOutput(t *testing.T) {
	for _, activation := range []uint64{3, 100} {
		header := profileHeader(t, activation)
		for _, mode := range []string{"supported", "missing", "future", "malformed"} {
			t.Run(fmt.Sprintf("A%d/%s", activation, mode), func(t *testing.T) {
				candidate := header
				fields, err := rlp.ListItems(header.Body)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "missing":
					fields = fields[:len(fields)-1]
					for len(fields) > 18 && (bytes.Equal(fields[len(fields)-1], []byte{0x80}) || bytes.Equal(fields[len(fields)-1], rlp.EmptyList)) {
						fields = fields[:len(fields)-1]
					}
				case "future":
					fields[len(fields)-1] = profileEncoding(t, profileEncoding(t, []any{uint64(2), big.NewInt(7), types.Hash{1}, new(big.Int).SetUint64(activation)}))
				case "malformed":
					fields[len(fields)-1] = profileEncoding(t, []byte{0xc0})
				}
				candidate.Body = profileEncoding(t, fields)
				fs := profileFixture(t, candidate)
				for _, from := range []string{"", "999999999"} {
					_, err := exportR01(fs, "/j", "/out", from, "")
					if err == nil || unsupportedSourceProfile(err) == (mode == "malformed") {
						t.Fatal("wrong profile refusal", mode, err)
					}
					if _, err := fs.ReadDir("/out"); !fsys.IsNotExist(err) {
						t.Fatal("profile refusal created output", err)
					}
					w := &r01Writer{}
					own := w.indexOwnInputs(fs, "/j")
					if w.profileErr == nil || len(own) != 0 {
						t.Fatal("own index used unsupported source", w.profileErr, len(own))
					}
				}
				if mode == "supported" {
					r, err := journal.OpenReader(fs, "/j")
					if err != nil {
						t.Fatal(err)
					}
					rec, err := readSourceRecord(r)
					if err != nil {
						t.Fatal("supported metadata not readable", err)
					}
					writer := &r01Writer{}
					if err := writer.record(rec, wal.Position{}); !errors.Is(err, journal.ErrDomainSourceUnsupported) {
						t.Fatal("output pass lost refusal", err)
					}
				}
			})
		}
	}
	for _, record := range []wal.Record{profileSigner(t, 3), profileFutureCore(t)} {
		fs := profileFixture(t, profileHeader(t, 0), record)
		var result map[string]any
		runJSON(t, fs, 69, &result, "export", "--dir", "/j", "--format", "r01", "--out", "/out", "--from", "999999999")
		if result["status"] != "unavailable" {
			t.Fatal(result)
		}
		if _, err := fs.ReadDir("/out"); !fsys.IsNotExist(err) {
			t.Fatal("future source created output", err)
		}
	}
}

// A normal original-segment bundle preserves metadata bytes. Extracting it
// is not independent physical or full-runtime restoration certification.
func TestDomainProfileOriginalBundlePreservesSelectedDeclaration(t *testing.T) {
	for _, activation := range []uint64{3, 100} {
		model := profileFixture(t, profileHeader(t, activation))
		reader, err := journal.OpenReader(model, "/j")
		if err != nil {
			t.Fatal(err)
		}
		record, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		identity := record.Body.(*journal.SegmentRec).Identity
		fs := fsys.NewMem()
		writer, err := journal.Open(journal.Options{FS: fs, Dir: "/input", Synchronous: true}, identity)
		if err != nil {
			t.Fatal(err)
		}
		input, err := inputlog.Encode(consensus.Start{})
		if err != nil {
			t.Fatal(err)
		}
		writer.Put(journal.Record{Body: &journal.StepRec{EngineRun: 1, Step: 1, InputKind: inputlog.KindStart, Input: input, Via: "engine", HeadNumber: types.HeightFromUint64(1)}})
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		bundle, err := exportBundle(fs, "/input", "/original.tar", "", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := fs.ReadFile("/original.tar")
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := journal.ReadBundle(bytes.NewReader(raw), fs, "/copy")
		if err != nil || len(manifest.Files) == 0 || len(manifest.Files) != len(bundle.Manifest.Files) {
			t.Fatal(manifest, err)
		}
		for _, file := range manifest.Files {
			original, err := fs.ReadFile("/input/" + file.Name)
			if err != nil {
				t.Fatal(err)
			}
			copied, err := fs.ReadFile("/copy/" + file.Name)
			if err != nil || !bytes.Equal(copied, original) {
				t.Fatal("original segment bytes changed", file.Name, err)
			}
		}
		copied, err := journal.ReadAll(fs, "/copy")
		if err != nil || len(copied) != 2 {
			t.Fatal(copied, err)
		}
		header := copied[0].Body.(*journal.SegmentRec)
		if err := header.ValidateDomainIdentity(); err != nil || !bytes.Equal(header.Core.DomainBytes, identity.Core.DomainBytes) {
			t.Fatal("bundle lost selected declaration", err)
		}
		var verified verifyResult
		runJSON(t, fs, 0, &verified, "verify", "--dir", "/copy")
		var stat statResult
		runJSON(t, fs, 0, &stat, "stat", "--dir", "/copy")
	}
	for _, future := range []wal.Record{profileSigner(t, 3), profileFutureCore(t)} {
		fs := profileFixture(t, profileHeader(t, 0), future)
		var result map[string]any
		runJSON(t, fs, 69, &result, "export", "--dir", "/j", "--format", "bundle", "--out", "/future.tar")
		if result["status"] != "unavailable" {
			t.Fatal(result)
		}
		if _, err := fs.ReadFile("/future.tar"); !fsys.IsNotExist(err) {
			t.Fatal("unsupported bundle left an output", err)
		}
	}
}
