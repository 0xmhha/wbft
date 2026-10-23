package journal

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

func deferredNormalMessage(t *testing.T) consensus.Message {
	t.Helper()
	k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("deferred-journal-normal")))
	if err != nil {
		t.Fatal(err)
	}
	m := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(11), Round: types.RoundFromUint64(1)}}
	p, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(p, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	return consensus.Message{Code: m.Code, Payload: raw, Peer: ecdsa.Address(k), RecvMono: 23}
}

func TestDeferredOriginAfterCloseOpenAndRetention(t *testing.T) {
	m := deferredNormalMessage(t)
	body, err := inputlog.EncodeDeferredMessage(m, inputlog.CaptureOrigin{Run: "first-writer", Capture: 17})
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range []bool{true, false} {
		t.Run(map[bool]string{true: "retained", false: "pruned"}[retained], func(t *testing.T) {
			fs := fsys.NewMem()
			runs := []string{"second-writer"}
			if retained {
				runs = append([]string{"first-writer"}, runs...)
			}
			for _, run := range runs {
				w, err := Open(Options{FS: fs, Dir: "/j", Synchronous: true}, Identity{Run: run})
				if err != nil {
					t.Fatal(err)
				}
				w.Put(Record{Body: &PeerRec{PeerIdx: 2, Addr: m.Peer, Event: "attached"}})
				// The later run legitimately receives the same signed message and
				// reuses its local capture number. It is not the original source.
				mono := time.Duration(9)
				if run == "second-writer" {
					mono = 90
				}
				w.Put(Record{Body: &MsgRec{Capture: 17, Dir: In, PeerIdx: 2, Code: uint64(m.Code), Payload: m.Payload, Mono: mono, Offer: transport.OfferQueued}})
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			r, err := OpenReader(fs, "/j")
			if err != nil {
				t.Fatal(err)
			}
			got, evidence, err := InspectDeferred(r, body)
			if err != nil || !reflect.DeepEqual(m, got) {
				t.Fatalf("functional input changed: %v", err)
			}
			if retained {
				if evidence.Status != "verified" || evidence.ReceiptMono == nil || *evidence.ReceiptMono != "9" {
					t.Fatalf("origin: %+v", evidence)
				}
			} else if evidence.Status != "unavailable" || evidence.Reason != "missing_capture" || evidence.ReceiptMono != nil {
				t.Fatalf("rebound to later writer: %+v", evidence)
			}
		})
	}
	got, e, err := InspectDeferred(nil, body)
	if err != nil || !reflect.DeepEqual(m, got) || e.Reason != "capture_resolver_unavailable" {
		t.Fatalf("no observer: %+v %v", e, err)
	}
}

func TestDeferredSegmentProfileAndLegacyBytes(t *testing.T) {
	id := ident()
	id.Core = CoreOptions{ChainConfig: []byte(`{"anzeon":{"wbft":{}}}`), ProposerPolicyProfile: CheckedProposerPolicyProfile}
	before, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Freeze the pre-extension field list, including its optional policy tail.
	old, err := rlp.Encode([]any{uint64(Format), uint64(1), id.Self, bytesOrEmpty(id.NodeID), bytesOrEmpty(id.BLSPublicKey), id.Run, id.Commit, bigOrZero(id.ChainID), id.GenesisHash, id.Mode, id.WireOffset, id.ConfigDigest, id.Core.ChainConfig, id.Core.Self, uint64(0), uint64(0), "", uint64(0), uint64(0), uint64(0), uint64(0), CheckedProposerPolicyProfile})
	if err != nil || !bytes.Equal(before, old) {
		t.Fatalf("disabled profile changed old segment bytes: %v", err)
	}
	id.Core.NextHeight = &DeferredOptions{Profile: DeferredInputProfile, Entries: 12, Bytes: 1 << 20, PerPeer: 4, PerSource: 3}
	raw, err := encodeBody(Record{Body: &SegmentRec{Identity: id}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeBody(KindSegment, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := record.Body.(*SegmentRec).Core
	if !reflect.DeepEqual(got.NextHeight, id.Core.NextHeight) {
		t.Fatal("receive limits lost from profile")
	}
	if _, err := got.Configuration(); err != nil {
		t.Fatal(err)
	}
}
