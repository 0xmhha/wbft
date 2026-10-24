package journal

import (
	"bytes"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/internal/fsys"
)

func signerRecordFixture() *SignerRec {
	return &SignerRec{Source: privval.Source{Version: privval.SourceVersion, Ref: privval.SourceRef{Namespace: "signer-reader", Signer: 1, Sequence: 1<<53 + 1}, Action: "initial", Result: "ok", Unavailable: "inspection_limits_required"}, Mono: 23, WallNs: ^uint64(0)}
}
func signerCallFixture() *SignerCallRec {
	return &SignerCallRec{Version: SignerCallSourceVersion, EngineRun: 1, Step: 2, Output: 1, Source: privval.SourceRef{Namespace: "signer-reader", Signer: 1, Sequence: 1<<53 + 1}, Result: "sent", Mono: 23, WallNs: ^uint64(0)}
}
func TestSignerRecordStrictPublicStateAndCallDomains(t *testing.T) {
	for _, kind := range []Kind{KindSigner, KindSignerCall} {
		t.Run(kind.String(), func(t *testing.T) {
			var body any
			if kind == KindSigner {
				body = signerRecordFixture()
			} else {
				body = signerCallFixture()
			}
			raw, err := encodeBody(Record{Body: body}, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			back, err := decodeBody(kind, raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := encodeBody(back, back.JSeq)
			if err != nil || back.JSeq != ^uint64(0) || !bytes.Equal(raw, again) {
				t.Fatal("durable public signer bytes changed", err)
			}
			for _, mode := range []string{"format", "version", "time", "action", "flags", "domain"} {
				t.Run(mode, func(t *testing.T) {
					var b []byte
					if kind == KindSigner {
						var w signerRLP
						if err := rlp.DecodeStrict(raw, &w); err != nil {
							t.Fatal(err)
						}
						switch mode {
						case "format":
							w.Format++
						case "version":
							w.Source.Source.Version++
						case "time":
							w.Source.Mono = 1 << 63
						case "action":
							w.Source.Source.Action = "unknown"
						case "flags":
							w.Source.Source.Reused = 2
						case "domain":
							w.Source.Source.WriteAttempted = 1
						}
						b, err = rlp.Encode(&w)
					} else {
						var w signerCallRLP
						if err := rlp.DecodeStrict(raw, &w); err != nil {
							t.Fatal(err)
						}
						switch mode {
						case "format":
							w.Format++
						case "version":
							w.Source.Version++
						case "time":
							w.Source.Mono = 1 << 63
						case "action":
							w.Source.Result = "unknown"
						case "flags":
							w.Source.Reused = 2
						case "domain":
							w.Source.Source.Namespace = ""
						}
						b, err = rlp.Encode(&w)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err = decodeBody(kind, b); err == nil {
						t.Fatal("contradictory public signer metadata accepted", kind, mode)
					}
				})
			}
		})
	}
}
func TestSignerRecordClassifiedQueueGaps(t *testing.T) {
	for _, body := range []any{signerRecordFixture(), signerCallFixture()} {
		r := Record{Body: body}
		kind, ok := kindOf(body)
		if !ok {
			t.Fatal("signer kind missing")
		}
		fs := fsys.NewMem()
		w, err := Open(Options{FS: fs, Dir: "/signer-gap", QueueRecords: 8, QueueBytes: 64}, ident())
		if err != nil {
			t.Fatal(err)
		}
		if size(r) < 512 || monoOf(r) != 23*time.Nanosecond {
			t.Fatal("public signer accounting missing")
		}
		w.Put(r)
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		records, err := ReadAll(fs, "/signer-gap")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rec := range records {
			if g, ok := rec.Body.(*GapRec); ok {
				for _, k := range g.ByKind {
					if k.Kind == uint64(kind) && k.Count == 1 {
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatal("public signer gap not classified", kind)
		}
	}
}
