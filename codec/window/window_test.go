package window

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

var fixtureLimits = Limits{ExtraBytes: 65536, Proofs: 16, SettlementRows: 16, Validators: 8}

func loadHeader(t *testing.T) (*types.Header, *Extra) {
	t.Helper()
	raw, err := os.ReadFile("testdata/epoch-header.rlp")
	if err != nil {
		t.Fatal(err)
	}
	h, err := codec.DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	x, err := Decode(h.Extra, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	return h, x
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := rlp.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenEnvelopeAndIndependentHash(t *testing.T) {
	h, x := loadHeader(t)
	raw, err := Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, h.Extra) || x.Observation.Settlement == nil || len(x.Observation.Settlement.Rows) != 4 {
		t.Fatal("nonempty settlement roundtrip")
	}
	var expected struct {
		BlockHash       string `json:"block_hash"`
		AuthorityDigest string `json:"authority_digest"`
	}
	b, err := os.ReadFile("testdata/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	hash, err := BlockHash(h, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hash[:]) != expected.BlockHash {
		t.Fatal("independent block hash")
	}
	type historicalEntry struct {
		Index   uint64
		Address types.Address
		Key     []byte
	}
	var entries []historicalEntry
	b, err = os.ReadFile("testdata/authority.rlp")
	if err != nil {
		t.Fatal(err)
	}
	if err = rlp.DecodeStrict(b, &entries); err != nil {
		t.Fatal(err)
	}
	var members []Member
	for i, e := range entries {
		if e.Index != uint64(i) {
			t.Fatal("historical index")
		}
		members = append(members, Member{e.Address, e.Key})
	}
	digest, err := AuthorityDigest(members, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != expected.AuthorityDigest {
		t.Fatal("independent authority digest")
	}
	members[0], members[1] = members[1], members[0]
	reordered, err := AuthorityDigest(members, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if reordered == digest {
		t.Fatal("authority order lost")
	}
}

func TestLegacyAndExplicitFormatRemainSeparate(t *testing.T) {
	h, x := loadHeader(t)
	raw, err := codec.EncodeExtra(x.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = codec.DecodeExtraBytes(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw, fixtureLimits); !errors.Is(err, ErrFormat) {
		t.Fatal("legacy implicitly promoted", err)
	}
	if _, err = codec.DecodeExtraBytes(h.Extra); err == nil {
		t.Fatal("legacy decoder changed")
	}
	if _, err = BlockHash(&types.Header{Extra: raw}, fixtureLimits); err == nil {
		t.Fatal("unsupported hash fallback")
	}
}

func TestRoundViewsPreserveProofAndObservation(t *testing.T) {
	h, x := loadHeader(t)
	original := append([]byte(nil), h.Extra...)
	want, err := BlockHash(h, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	proofs := encoded(t, mustWire(t, x).Proofs)
	observation := encoded(t, mustWire(t, x).Observation)
	for _, round := range []uint32{0, 1, 2, ^uint32(0)} {
		view, err := FilteredHeader(h, round, fixtureLimits)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Decode(view.Extra, fixtureLimits)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Legacy.Round != round || parsed.Legacy.PreparedSeal != nil || parsed.Legacy.CommittedSeal != nil {
			t.Fatal("current round/seals")
		}
		if !bytes.Equal(encoded(t, mustWire(t, parsed).Proofs), proofs) || !bytes.Equal(encoded(t, mustWire(t, parsed).Observation), observation) {
			t.Fatal("committed observation changed")
		}
		got, err := BlockHash(view, fixtureLimits)
		if err != nil || got != want {
			t.Fatal("round changed block hash", err)
		}
		for _, phase := range []types.SealType{types.PrepareSeal, types.CommitSeal} {
			msg, err := SealData(view, round, phase, fixtureLimits)
			if err != nil || len(msg) != 32 {
				t.Fatal("signing domain", err)
			}
		}
	}
	if !bytes.Equal(original, h.Extra) {
		t.Fatal("input mutated")
	}
	// These copies are offline byte diagnostics, not network proposals.
	x.Proofs = x.Proofs[:len(x.Proofs)-1]
	edited := h.Copy()
	edited.Extra, err = Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	different, err := BlockHash(edited, fixtureLimits)
	if err != nil || different == want {
		t.Fatal("proof not hash bound", err)
	}
	_, x = loadHeader(t)
	x.Observation.ResultStateRoot[0] ^= 1
	edited.Extra, err = Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	different, err = BlockHash(edited, fixtureLimits)
	if err != nil || different == want {
		t.Fatal("observation not hash bound", err)
	}
}

func mustWire(t *testing.T, x *Extra) *extraRLP {
	t.Helper()
	w, err := wire(x)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestFullPrecisionHeightsCursorsAndCounts(t *testing.T) {
	_, x := loadHeader(t)
	huge := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(23))
	for i := range x.Proofs {
		x.Proofs[i].Height = types.MustHeightFromBig(new(big.Int).Add(huge, x.Proofs[i].Height.Big()))
	}
	x.Observation.Settlement.Previous = types.MustHeightFromBig(huge)
	x.Observation.Settlement.Through = types.MustHeightFromBig(new(big.Int).Add(huge, big.NewInt(1)))
	row := &x.Observation.Settlement.Rows[0]
	row.EligiblePrepare = new(big.Int).Lsh(big.NewInt(1), 256)
	row.ObservedPrepare = new(big.Int).Sub(row.EligiblePrepare, big.NewInt(1))
	raw, err := Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Proofs[0].Height.Cmp(x.Proofs[0].Height) != 0 || decoded.Observation.Settlement.Previous.Cmp(x.Observation.Settlement.Previous) != 0 || decoded.Observation.Settlement.Rows[0].EligiblePrepare.Cmp(row.EligiblePrepare) != 0 {
		t.Fatal("full value truncated")
	}
	decoded.Proofs[0].Height = types.HeightFromUint64(23)
	low, err := Encode(decoded, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, low) {
		t.Fatal("low64 collision")
	}
}

func TestClosedCopiesRejectUnsupportedStructures(t *testing.T) {
	h, _ := loadHeader(t)
	cases := map[string]func(*extraRLP){
		"version":                func(w *extraRLP) { w.Version = 3 },
		"observation_version":    func(w *extraRLP) { w.Observation.Version = 2 },
		"legacy_blob":            func(w *extraRLP) { w.Legacy = encoded(t, []byte(w.Legacy)) },
		"duplicate_target_phase": func(w *extraRLP) { w.Proofs = append(w.Proofs[:1], w.Proofs...) },
		"phase":                  func(w *extraRLP) { w.Proofs[0].Phase = 2 },
		"signature_length":       func(w *extraRLP) { w.Proofs[0].Signature = w.Proofs[0].Signature[:95] },
		"bitmap_padding":         func(w *extraRLP) { w.Proofs[0].Bitmap = append(w.Proofs[0].Bitmap, 0) },
		"count_range": func(w *extraRLP) {
			w.Observation.Settlement.Rows[0].ObservedPrepare = new(big.Int).Add(w.Observation.Settlement.Rows[0].EligiblePrepare, big.NewInt(1))
		},
		"row_order":    func(w *extraRLP) { s := w.Observation.Settlement; s.Rows[0], s.Rows[1] = s.Rows[1], s.Rows[0] },
		"cursor_order": func(w *extraRLP) { w.Observation.Settlement.Through = big.NewInt(0) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			var w extraRLP
			if err := rlp.DecodeStrict(h.Extra, &w); err != nil {
				t.Fatal(err)
			}
			edit(&w)
			if _, err := Decode(encoded(t, w), fixtureLimits); !errors.Is(err, ErrFormat) {
				t.Fatal("copy accepted", err)
			}
		})
	}
	if _, err := Decode(append(append([]byte(nil), h.Extra...), 0), fixtureLimits); !errors.Is(err, ErrFormat) {
		t.Fatal("trailing bytes", err)
	}
}

func TestRequiredLimitsAndAbsentSettlement(t *testing.T) {
	h, x := loadHeader(t)
	limits := []Limits{{}, {ExtraBytes: uint64(len(h.Extra) - 1), Proofs: 16, SettlementRows: 16, Validators: 8}, {ExtraBytes: 65536, Proofs: 1, SettlementRows: 16, Validators: 8}, {ExtraBytes: 65536, Proofs: 16, SettlementRows: 1, Validators: 8}, {ExtraBytes: 65536, Proofs: 16, SettlementRows: 16, Validators: 1}}
	for _, l := range limits {
		if _, err := Decode(h.Extra, l); !errors.Is(err, ErrLimit) {
			t.Fatal("missing limit", l, err)
		}
	}
	x.Observation.Settlement = nil
	raw, err := Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, fixtureLimits)
	if err != nil || decoded.Observation.Settlement != nil {
		t.Fatal("absent settlement", err)
	}
	x.Observation.Settlement = &Settlement{Previous: types.HeightFromUint64(3), Through: types.HeightFromUint64(3)}
	raw, err = Encode(x, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(raw, fixtureLimits)
	if err != nil || decoded.Observation.Settlement == nil {
		t.Fatal("empty interval differs from absence", err)
	}
}
