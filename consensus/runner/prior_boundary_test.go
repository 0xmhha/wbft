package runner

import (
	"bytes"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func TestPriorBoundaryPreservesBothOriginalFormats(t *testing.T) {
	past, next := newKeys(t, 4), newKeys(t, 5)
	head := block(t, 10, 1, past.addrs[0], types.Hash{9}).Header
	for _, format := range []uint8{walFormat, nextHeightFormat} {
		for _, unavailable := range []bool{false, true} {
			base, err := encodeBoundary(walEndHeight, boundaryRec{From: head.Number.AddUint64(1), Head: head, Validators: next.vs, Replayed: true})
			if err != nil {
				t.Fatal(err)
			}
			if format == nextHeightFormat {
				base.Format = nextHeightFormat
				base.Body, err = rlp.Encode(&deferredBoundary{Boundary: base.Body, Limits: NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}, Pending: []deferredRecord{}})
				if err != nil {
					t.Fatal(err)
				}
			}
			original := append([]byte(nil), base.Body...)
			vs := past.vs
			if unavailable {
				vs = nil
			}
			p, err := consensus.NewPriorHeadSource(head, vs)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := encodePriorBoundary(base, p, head)
			if err != nil || wrapped.Format != priorHeadFormat || !bytes.Equal(base.Body, original) {
				t.Fatal("base boundary was changed", err)
			}
			restored, source, err := decodePriorBoundary(wrapped)
			if err != nil || restored.Format != base.Format || restored.Kind != base.Kind || !bytes.Equal(restored.Body, original) || source.ValidateHead(head) != nil {
				t.Fatal("boundary identity changed", err)
			}
			decoded, pending, err := decodeRunnerBoundary(restored)
			if err != nil || decoded.Validators.Len() != 5 || (pending != nil) != (format == nextHeightFormat) {
				t.Fatal("successor set or deferred profile changed", err)
			}
			if unavailable {
				if source.Validators != nil {
					t.Fatal("unavailable source replaced by successor set")
				}
			} else if source.Validators == nil || source.Validators.Len() != 4 || consensus.ValsetDigest(source.Validators) != consensus.ValsetDigest(past.vs) {
				t.Fatal("historical authority replaced by successor")
			}
			if source.Hash != codec.BlockHash(head) || source.MatchesLookup(head.Number.AddUint64(1), codec.BlockHash(head)) {
				t.Fatal("historical query was conflated")
			}
		}
	}
}

func TestPriorBoundaryKeepsDeferredReservation(t *testing.T) {
	k := newKeys(t, 4)
	head := block(t, 10, 1, k.addrs[0], types.Hash{9}).Header
	b, err := encodeBoundary(walRunStart, boundaryRec{From: head.Number.AddUint64(1), Head: head, Validators: k.vs})
	if err != nil {
		t.Fatal(err)
	}
	message := block(t, 11, 1, k.addrs[1], codec.BlockHash(head))
	raw := k.vote(t, 1, codec.CodePrepare, view(11, 0), message)
	d := deferredRecord{ID: 1, Code: uint64(codec.CodePrepare), Payload: raw, Peer: k.addrs[1], RecvMono: 7, CaptureRun: "owned-normal-source", Capture: 2}
	b.Format = nextHeightFormat
	b.Body, err = rlp.Encode(&deferredBoundary{Boundary: b.Body, Limits: NextHeightLimits{Entries: 4, Bytes: 1 << 20, PerPeer: 2, PerSource: 2}, Pending: []deferredRecord{d}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := consensus.NewPriorHeadSource(head, k.vs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := encodePriorBoundary(b, p, head)
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := decodePriorBoundary(w)
	if err != nil {
		t.Fatal(err)
	}
	_, pending, err := decodeRunnerBoundary(restored)
	if err != nil || pending == nil || len(pending.Pending) != 1 || !sameDeferred(d, pending.Pending[0]) {
		t.Fatal("normal deferred source or reservation lost", err)
	}
	if len(raw) == 0 || pending.Pending[0].CaptureRun != d.CaptureRun {
		t.Fatal("normal source was replaced")
	}
}
