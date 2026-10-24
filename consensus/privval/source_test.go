package privval

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestSourceNormalSigningStorageAndReopenPair(t *testing.T) {
	var sources []Source
	var original []byte
	var signatures []VoteSignature
	for _, enabled := range []bool{false, true} {
		fs := fsys.NewMem()
		if err := fs.MkdirAll("/pv", 0700); err != nil {
			t.Fatal(err)
		}
		options := Options{FS: fs}
		if enabled {
			options.Sources = &SourceOptions{Namespace: "normal-signer", Records: 64, Bytes: 4 << 20, Observe: func(s Source) { sources = append(sources, s) }}
		}
		s, err := NewKeySignerWithOptions(options, testKey(0), "/pv/state")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.InitSignFloor(types.HeightFromUint64(0)); err != nil {
			t.Fatal(err)
		}
		if err = s.ClearSignFloor(); err != nil {
			t.Fatal(err)
		}
		request := preprepare(10, 0, 1)
		b := request.Msg.Proposal
		prepare := VoteRequest{Msg: &codec.Message{Code: codec.CodePrepare, View: view(10, 0), Digest: codec.BlockHash(b.Header)}, SealData: codec.SealData(b.Header, 0, types.PrepareSeal)}
		commit := VoteRequest{Msg: &codec.Message{Code: codec.CodeCommit, View: view(10, 0), Digest: codec.BlockHash(b.Header)}, SealData: codec.SealData(b.Header, 0, types.CommitSeal)}
		var got []VoteSignature
		for _, req := range []VoteRequest{request, prepare, commit} {
			sig, ref, err := s.SignVoteWithSource(req)
			if err != nil {
				t.Fatal(err)
			}
			if enabled && (ref.Namespace != "normal-signer" || ref.Signer == 0 || ref.Sequence == 0) {
				t.Fatal("original operation reference missing", ref)
			}
			got = append(got, sig)
		}
		// Reopening uses the actual persisted state, with a new signer lifetime.
		s, err = NewKeySignerWithOptions(options, testKey(0), "/pv/state")
		if err != nil {
			t.Fatal(err)
		}
		reused, err := s.SignVote(commit)
		if err != nil || !reused.Reused || !bytes.Equal(reused.Signature, got[2].Signature) {
			t.Fatal("normal retransmission did not reuse stored signature", err)
		}
		got = append(got, reused)
		stored, err := fs.ReadFile("/pv/state")
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			original = stored
			signatures = got
		} else if !bytes.Equal(original, stored) || !reflect.DeepEqual(signatures, got) {
			t.Fatal("observation changed actual stored state or returned signatures")
		}
	}
	limits := SourceLimits{Lifetimes: 4, Operations: 64, Records: 128, Bytes: 16 << 20}
	report, err := CheckSources(sources, limits)
	if err != nil || report.Status != "consistent" || report.Lifetimes != 2 || report.Signed != 3 || report.Reused != 1 || report.Writes != 5 || report.PhysicalStatus != "unavailable" {
		t.Fatal("normal public state did not reconstruct", report, err)
	}
	// No signer or filesystem is used after this point. Only detached metadata
	// is changed; refusal cases do not create new live signing requests.
	for _, mode := range []string{"initial_missing", "duplicate", "gap", "before", "after", "write", "write_result", "decision", "signature", "seal", "request_code", "released", "floor", "lifetime", "identity", "limit"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := rlp.Encode(sources)
			if err != nil {
				t.Fatal(err)
			}
			var copied []Source
			if err = rlp.DecodeStrict(raw, &copied); err != nil {
				t.Fatal(err)
			}
			l := limits
			switch mode {
			case "initial_missing":
				copied = copied[1:]
			case "duplicate":
				copied = append(copied, copied[3])
			case "gap":
				copied = append(copied[:4], copied[5:]...)
			case "before":
				copied[3].Before[0] ^= 1
			case "after":
				copied[3].After[0] ^= 1
			case "write":
				copied[3].Write[0] ^= 1
			case "write_result":
				copied[3].WriteResult = "failed"
			case "decision":
				copied[3].Result = "double_sign"
			case "signature":
				copied[3].Signature[0] ^= 1
			case "seal":
				copied[4].Seal[0] ^= 1
			case "request_code":
				copied[4].RequestCode = uint64(codec.CodeCommit)
			case "released":
				copied[3].BadBlockReleased = 2
			case "floor":
				copied[1].Floor = "1"
			case "lifetime":
				copied[3].Ref.Signer++
			case "identity":
				copied[3].Address[0] ^= 1
			case "limit":
				l.Bytes = 1
			}
			got, e := CheckSources(copied, l)
			if got.Status == "consistent" {
				t.Fatal("contradictory copied public state accepted", mode, got, e)
			}
		})
	}
	// Callback delivery can be reordered; original mutex sequence controls it.
	reversed := slices.Clone(sources)
	slices.Reverse(reversed)
	report, err = CheckSources(reversed, limits)
	if err != nil || report.Status != "consistent" {
		t.Fatal("delivery order replaced original mutex order", report, err)
	}
}

func TestSourceCallbackRunsUnlockedAndCopiesAreDetached(t *testing.T) {
	fs := fsys.NewMem()
	if err := fs.MkdirAll("/pv", 0700); err != nil {
		t.Fatal(err)
	}
	var signer *FileSigner
	count := 0
	observer := func(s Source) {
		count++
		if signer != nil {
			_ = signer.Empty()
		}
		for _, b := range [][]byte{s.Before, s.After, s.Request, s.SealData, s.Signature, s.Seal, s.Write, s.BLSPublicKey} {
			if len(b) > 0 {
				b[0] ^= 1
			}
		}
	}
	var err error
	signer, err = NewKeySignerWithOptions(Options{FS: fs, Sources: &SourceOptions{Namespace: "detached-signer", Records: 64, Bytes: 4 << 20, Observe: observer}}, testKey(0), "/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	req := preprepare(10, 0, 1)
	sig, err := signer.SignVote(req)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, req, sig)
	stored, err := fs.ReadFile("/pv/state")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeState(stored); err != nil || count != 2 {
		t.Fatal("detached callback damaged original signer", err, count)
	}
}

func TestSourceCopyLimitsPreserveNormalSigningAndFrozenNamespace(t *testing.T) {
	for _, mode := range []string{"bytes", "records", "namespace"} {
		t.Run(mode, func(t *testing.T) {
			fs := fsys.NewMem()
			if err := fs.MkdirAll("/pv", 0700); err != nil {
				t.Fatal(err)
			}
			var observations []Source
			options := &SourceOptions{Namespace: "frozen-signer", Records: 64, Bytes: 4 << 20, Observe: func(s Source) { observations = append(observations, s) }}
			switch mode {
			case "bytes":
				options.Bytes = 1
			case "records":
				options.Records = 0
			case "namespace":
				options.Namespace = ""
			}
			originalNamespace := options.Namespace
			signer, err := NewKeySignerWithOptions(Options{FS: fs, Sources: options}, testKey(0), "/pv/state")
			if err != nil {
				t.Fatal(err)
			}
			options.Namespace = "later-caller-change"
			request := preprepare(10, 0, 1)
			sig, err := signer.SignVote(request)
			if err != nil {
				t.Fatal("diagnostic copy limit changed normal signing", err)
			}
			verify(t, request, sig)
			stored, err := fs.ReadFile("/pv/state")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeState(stored); err != nil {
				t.Fatal(err)
			}
			if len(observations) != 2 {
				t.Fatal("original operations missing")
			}
			for _, s := range observations {
				if s.Ref.Namespace != originalNamespace || s.Unavailable == "" || ValidateSource(s) != nil {
					t.Fatal("copy limit or namespace not retained", s.Ref, s.Unavailable)
				}
			}
			report, err := CheckSources(observations, SourceLimits{Lifetimes: 4, Operations: 16, Records: 128, Bytes: 4 << 20})
			if err != nil || report.Status != "unavailable" {
				t.Fatal("limited source accepted", report, err)
			}
		})
	}
}
