package codec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorKey is key_i of A-02 §8.1.
func vectorKey(t testing.TB, i int) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.PrivateKeyFromBytes(keccak.Sum256Bytes([]byte("wbft-spec-vector-key-" + string(rune('0'+i)))))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// headerH is the header H of A-02 §8.4 (chain 8282, block 2, proposer key 0).
func headerH(t testing.TB) *types.Header {
	t.Helper()
	reveal, err := ecdsa.SignData(RandaoData(big.NewInt(8282), types.HeightFromUint64(2)), vectorKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	x := &types.WBFTExtra{
		VanityData:   make([]byte, 32),
		RandaoReveal: reveal,
		GasTip:       new(big.Int).SetUint64(types.InitialGasTip),
	}
	extra, err := EncodeExtra(x)
	if err != nil {
		t.Fatal(err)
	}
	empty := types.Hash(unhex(t, "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"))
	return &types.Header{
		ParentHash:  types.Hash(bytes.Repeat([]byte{0x11}, 32)),
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    ecdsa.Address(vectorKey(t, 0)),
		Root:        types.Hash(bytes.Repeat([]byte{0x22}, 32)),
		TxHash:      empty,
		ReceiptHash: empty,
		Difficulty:  big.NewInt(1),
		Number:      types.HeightFromUint64(2),
		GasLimit:    105000000,
		Time:        1700000002,
		Extra:       extra,
		BaseFee:     big.NewInt(20000000000000),
	}
}

// A-03 §9.3.
func TestHeaderH(t *testing.T) {
	h := headerH(t)
	wantExtra := "f872a0" + strings.Repeat("00", 32) +
		"b8416243139f0e6b881248e468a6566eb5ed9c278bb1b54d8bd46ebe50055bcb92a5435af24253453da96c927a47f9d23f4c19eb2f5b53ead248e93d0182be94c44800" +
		"80c0c080c0c086191a20322000c0"
	if got := hex.EncodeToString(h.Extra); got != wantExtra {
		t.Fatalf("extra\n got %s\nwant %s", got, wantExtra)
	}
	enc, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 628 || !bytes.HasPrefix(enc, unhex(t, "f90271")) {
		t.Fatalf("header RLP of %d bytes, prefix %x", len(enc), enc[:3])
	}
	hash := BlockHash(h)
	if hex.EncodeToString(hash[:]) != "6284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e" {
		t.Fatalf("block hash %x", hash)
	}
	dec, err := DecodeHeader(enc)
	if err != nil {
		t.Fatal(err)
	}
	re, _ := EncodeHeader(dec)
	if !bytes.Equal(re, enc) {
		t.Fatal("header re-encoding differs")
	}
	for r, want := range map[uint32]string{
		0: "6284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e",
		1: "12fbf50df755a39e84a982f2cee1ad16ca800ee1e7a74f980cc7948b6d515752",
		2: "9493c5c1781d9d10df8b95545bc4272ad33a6c30b0b5319eade35b513dcf2d4e",
	} {
		got := HashWithRound(h, r)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("hash_with_round(H, %d) = %x, want %s", r, got, want)
		}
	}
	// A-02 §8.4 seal data.
	for _, c := range []struct {
		round uint32
		t     types.SealType
		want  string
	}{
		{0, types.PrepareSeal, "9634606e7f65a734cd97a24d8a6458383e38f5e5c9b679864b15d0db09b94391"},
		{0, types.CommitSeal, "087eccbdf4ac7846d8255e2d0ef5e6e5f0b344fef86c625e12b9ba123eb3ee50"},
		{2, types.PrepareSeal, "5e2e30b10f096d24641da9829661c6df27738aab23b7071206bcb845c2691152"},
		{2, types.CommitSeal, "364771f56f2ddcf3f80b9f9fdc5085a3d3f8cbc23c80578e5be1543c2aab2e17"},
	} {
		if got := hex.EncodeToString(SealData(h, c.round, c.t)); got != c.want {
			t.Errorf("seal_data(H, %d, %d) = %s, want %s", c.round, c.t, got, c.want)
		}
	}
}

// A-03 §9.3 "other checks" and WBFT-ENC-084.
func TestBlockHashFallbacks(t *testing.T) {
	h := headerH(t)
	d2 := h.Copy()
	d2.Difficulty = big.NewInt(2)
	if got := BlockHash(d2); hex.EncodeToString(got[:]) != "170754e9c004b76a6670c61ac483945b4e247ab089331ecd3c168421340cc9f3" {
		t.Errorf("difficulty 2: %x", got)
	}
	bad := h.Copy()
	bad.Extra = append(bad.Extra, 0)
	if got := BlockHash(bad); hex.EncodeToString(got[:]) != "f54bd294c2e969aeae6134f0733e394379523e4f0f38136ab48a267cb59fd8c4" {
		t.Errorf("undecodable extra: %x", got)
	}
	if got, want := BlockHash(bad), HeaderHash(bad); got != want {
		t.Error("undecodable extra must hash with the Ethereum rule")
	}
	// seal_data of a header whose extra does not decode is a constant.
	if got := hex.EncodeToString(SealData(bad, 0, types.PrepareSeal)); got != "f3aac67c5fc8b34464e4fe705b4570279ead9d482adf0d2c875a970920027699" {
		t.Errorf("seal data of undecodable extra: %s", got)
	}
	if _, err := FilteredHeader(bad, 0); err == nil {
		t.Error("FilteredHeader of undecodable extra must fail")
	}
}

// A-03 §9.1.
func TestExtraDecodeTable(t *testing.T) {
	ok := []string{"ca808080c0c080c0c080c0", "cc808080c0c080c28080c080c0"}
	for _, s := range ok {
		x, err := DecodeExtraBytes(unhex(t, s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		re, err := EncodeExtra(x)
		if err != nil || hex.EncodeToString(re) != s {
			t.Errorf("%s re-encodes to %x (%v)", s, re, err)
		}
		if x.GasTip == nil || x.GasTip.Sign() != 0 {
			t.Errorf("%s: gas tip %v, want present 0", s, x.GasTip)
		}
	}
	x, _ := DecodeExtraBytes(unhex(t, ok[0]))
	if x.PreparedSeal != nil || x.EpochInfo != nil {
		t.Error("absent seal or epoch info decoded as present")
	}
	x, _ = DecodeExtraBytes(unhex(t, ok[1]))
	if x.PreparedSeal == nil {
		t.Error("present empty prepared seal decoded as absent")
	}
	bad := []string{
		"ca808080808080c0c080c0",
		"ca808080c0c080c0c0c0c0",
		"ca808000c0c080c0c080c0",
		"ce8080850100000000c0c080c0c080c0",
		"ca808080c0c080c0c000c0",
		"cb808080c0c080c0c08100c0",
		"c9808080c0c080c0c080",
		"cb808080c0c080c0c080c080",
		"ca808080c0c080c0c080c000",
	}
	for _, s := range bad {
		if _, err := DecodeExtraBytes(unhex(t, s)); err == nil {
			t.Errorf("%s decoded", s)
		}
	}
}

// A-03 §9.2.
func TestSealerSet(t *testing.T) {
	tests := []struct {
		idx  []uint32
		want string
	}{
		{nil, ""}, {[]uint32{0}, "01"}, {[]uint32{0, 1, 2}, "07"}, {[]uint32{1, 3}, "0a"},
		{[]uint32{0, 8}, "0101"}, {[]uint32{9}, "0002"}, {[]uint32{15}, "0080"}, {[]uint32{16}, "000001"},
	}
	for _, tt := range tests {
		var s types.SealerSet
		for _, i := range tt.idx {
			s.SetSealer(i)
			s.SetSealer(i) // idempotent
		}
		if hex.EncodeToString(s) != tt.want {
			t.Errorf("%v: %x, want %s", tt.idx, []byte(s), tt.want)
		}
		got := s.Sealers()
		if len(got) != len(tt.idx) {
			t.Errorf("%v: sealers %v", tt.idx, got)
		}
	}
	if got := types.SealerSet(unhex(t, "0700")).Sealers(); len(got) != 3 {
		t.Errorf("non-minimal bitmap names %v", got)
	}
}

// A-03 §9.4.
func TestGenesisExtra(t *testing.T) {
	ei := &types.EpochInfo{}
	keys := []string{
		"8eaaca1bbb29c07cb653b346e8434bb6b3bc63a4bb7c8dfea5c46bae2473646fe8041e3ff81da70bba7effda935a4576",
		"8a8f913a1bac306b3b1661fc78ce376a650341ce314f7c0f615fc7abf3722eb6c256046483c266d3e03ce82edbed13a3",
		"976a4cd50f07ad6fb3fc0a7a27a803212be7cf84b779d9a5562af81316187dec8ee319a0ce421c020dc1bf1faa494abe",
		"aa6b0cda839b65a5e2e556484ccb3d67fac59c1cc66ab2bf1b9160ecee30a0deb6dbbad04836ca99ceb74c225a0c184e",
	}
	for i := 0; i < 4; i++ {
		ei.Candidates = append(ei.Candidates, types.Candidate{Addr: ecdsa.Address(vectorKey(t, i)), Diligence: types.DefaultDiligence})
		ei.Validators = append(ei.Validators, uint32(i))
		ei.BLSPublicKeys = append(ei.BLSPublicKeys, unhex(t, keys[i]))
	}
	b, err := EncodeExtra(&types.WBFTExtra{GasTip: new(big.Int).SetUint64(types.InitialGasTip), EpochInfo: ei})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 330 || !bytes.HasPrefix(b, unhex(t, "f90147 80 80 80 c0 c0 80 c0 c0 86191a20322000 f90135 f868 d994")) {
		t.Fatalf("genesis extra %x", b)
	}
	if hex.EncodeToString(b[len(b)-49:len(b)-48]) != "b0" {
		t.Error("last key not a 48-byte string")
	}
	if e, _ := EncodeExtra(&types.WBFTExtra{EpochInfo: &types.EpochInfo{}}); !bytes.HasSuffix(e, unhex(t, "c3c0c0c0")) {
		t.Errorf("empty EpochInfo encodes as %x", e)
	}
}

// A-03 §9.6: PREPARE by key 1.
func TestPrepareMessage(t *testing.T) {
	wire := unhex(t, "f8caf8850280a06284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1eb860b9ed2c8ca8ef593fa5b1749082a5bc211460b913a9c5a3eec8770d5acff6bf6501dfa61735f6cdd045e5e75a9489801a0bca5554be5abae320e5d883dae61838ad5765c1427cb4a5672dabd5649969760505ff7aaee60aa2e2e5a623af1726a1b841210a2b4c90e9be64976a7b81aab05aad51146d6abc3bd0061f7a35af8290e6ae31038a77129d7441c68ade4ea87372a481e343a794b711f3cb8ff5b4d6b7bd5501")
	m, err := DecodeMessage(CodePrepare, wire)
	if err != nil {
		t.Fatal(err)
	}
	if m.View.Sequence.String() != "2" || !m.View.Round.IsZero() {
		t.Errorf("view %s/%s", m.View.Sequence, m.View.Round)
	}
	re, err := EncodeMessage(m)
	if err != nil || !bytes.Equal(re, wire) {
		t.Fatalf("re-encoding differs: %v", err)
	}
	p, err := SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 138 || !bytes.HasPrefix(p, unhex(t, "f888 13 f885 02 80 a0")) {
		t.Errorf("signing payload %x", p)
	}
	signer, err := ecdsa.RecoverDataSigner(p, m.Signature)
	if err != nil || signer != ecdsa.Address(vectorKey(t, 1)) {
		t.Errorf("signer %x, %v", signer, err)
	}
	k := DedupKey(wire)
	if hex.EncodeToString(k[:]) != "7e20c27fc270ed22dfe8b8ee9dbc97f2b9672cf8fd6dc360fbb0321e7f4d4aec" {
		t.Errorf("dedup key %x", k)
	}
	if _, err := SigningPayload(m, true, big.NewInt(8282)); !errors.Is(err, ErrChainIDPayload) {
		t.Errorf("payload with chain id: %v", err)
	}
	// The same payload as COMMIT decodes, but its signing payload differs.
	c, err := DecodeMessage(CodeCommit, wire)
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := SigningPayload(c, false, nil)
	if bytes.Equal(pc, p) {
		t.Error("PREPARE and COMMIT signing payloads are equal")
	}
	if _, err := DecodeMessage(CodePreprepare, wire); err == nil {
		t.Error("PREPARE payload decoded as PRE-PREPARE")
	}
	for _, code := range []Code{CodeIstanbul, 0x16, 0} {
		if _, err := DecodeMessage(code, wire); !errors.Is(err, ErrUnknownCode) {
			t.Errorf("code %#x: %v", code, err)
		}
	}
}

// A-03 §9.6: ROUND-CHANGE decoding edge cases.
func TestRoundChangeEdgeCases(t *testing.T) {
	tests := []struct {
		wire      string
		ok        bool
		reencoded string
	}{
		{"c9c6c30201c081aac0c0", true, "c9c6c30201c081aac0c0"},
		{"c9c6c30201c081aa8080", true, "c9c6c30201c081aac0c0"},
		{"c9c6c30201c081aa0500", true, "c9c6c30201c081aac0c0"},
		{"c8c6c30201c081aac0", false, ""},
		{"cac6c30201c081aac0c0c0", false, ""},
		{"c9c6c30201c081aac0c000", false, ""},
	}
	for _, tt := range tests {
		m, err := DecodeMessage(CodeRoundChange, unhex(t, tt.wire))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err %v", tt.wire, err)
			continue
		}
		if !tt.ok {
			continue
		}
		re, err := EncodeMessage(m)
		if err != nil || hex.EncodeToString(re) != tt.reencoded {
			t.Errorf("%s re-encodes to %x (%v)", tt.wire, re, err)
		}
		p, _ := SigningPayload(m, false, nil)
		if hex.EncodeToString(p) != "c515c30201c0" {
			t.Errorf("%s signing payload %x", tt.wire, p)
		}
	}
	// prepared = [0, 0x00..00] is accepted and signs as prepared = [].
	zero := encodeRCWithPrepared(t, "e280a0"+strings.Repeat("00", 32))
	m, err := DecodeMessage(CodeRoundChange, zero)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := SigningPayload(m, false, nil); hex.EncodeToString(p) != "c515c30201c0" {
		t.Errorf("zero digest signing payload %x", p)
	}
	one := encodeRCWithPrepared(t, "e201a0"+strings.Repeat("00", 31)+"01")
	m, err = DecodeMessage(CodeRoundChange, one)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := SigningPayload(m, false, nil); hex.EncodeToString(p) != "e715e50201e201a0"+strings.Repeat("00", 31)+"01" {
		t.Errorf("prepared signing payload %x", p)
	}
	for _, prepared := range []string{"c180", "e380a0" + strings.Repeat("00", 32) + "01"} {
		if _, err := DecodeMessage(CodeRoundChange, encodeRCWithPrepared(t, prepared)); err == nil {
			t.Errorf("prepared %s accepted", prepared)
		}
	}
}

// encodeRCWithPrepared builds [[[2, 1, prepared], 0xaa], c0, c0].
func encodeRCWithPrepared(t *testing.T, prepared string) []byte {
	t.Helper()
	payload := append(unhex(t, "0201"), unhex(t, prepared)...)
	payload = append([]byte{byte(0xc0 + len(payload))}, payload...)
	if len(payload) > 56 {
		payload = append([]byte{0xf8, byte(len(payload) - 1)}, payload[1:]...)
	}
	signed := append(append([]byte{}, payload...), 0x81, 0xaa)
	signed = listOf(signed)
	return listOf(append(signed, 0xc0, 0xc0))
}

func listOf(content []byte) []byte {
	if len(content) < 56 {
		return append([]byte{byte(0xc0 + len(content))}, content...)
	}
	return append([]byte{0xf8, byte(len(content))}, content...)
}

// A-03 §9.6: PRE-PREPARE with block H and empty justification, and with an
// absent proposal.
func TestPreprepareMessage(t *testing.T) {
	h := headerH(t)
	block := &types.Block{Header: h, Body: types.BodyRaw{{0xc0}, {0xc0}}}
	m := &Message{Code: CodePreprepare, View: types.View{Sequence: types.HeightFromUint64(2)}, Proposal: block}
	p, err := SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 642 || !bytes.HasPrefix(p, unhex(t, "f9027f12f9027b0280f90276f90271")) {
		t.Fatalf("signing payload of %d bytes: %x", len(p), p[:16])
	}
	sig, err := ecdsa.SignData(p, vectorKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = sig
	wire, err := EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 714 || !bytes.HasSuffix(wire, unhex(t, "c2c0c0")) {
		t.Fatalf("wire of %d bytes", len(wire))
	}
	if hex.EncodeToString(sig) != "3a5f2bea6f18e89d704efb5ac54790314b24bdd0ef1121de7ad5ec7f68f1199f7da8d2981c15a295929cdd93792580dd29076e34f0e25b8f1b154654c57b13df01" {
		t.Errorf("signature %x", sig)
	}
	d, err := DecodeMessage(CodePreprepare, wire)
	if err != nil {
		t.Fatal(err)
	}
	re, _ := EncodeMessage(d)
	if !bytes.Equal(re, wire) {
		t.Error("PRE-PREPARE re-encoding differs")
	}
	if _, err := DecodeMessage(CodePreprepare, unhex(t, "c9c5c30280c080c2c0c0")); err == nil {
		t.Error("absent proposal decoded")
	}
}

func TestDedupKeyLengths(t *testing.T) {
	for _, n := range []int{0, 1, 55, 56, 256} {
		p := bytes.Repeat([]byte{0x7f}, n)
		var want []byte
		switch {
		case n == 1:
			want = p
		case n <= 55:
			want = append([]byte{byte(0x80 + n)}, p...)
		case n < 256:
			want = append([]byte{0xb8, byte(n)}, p...)
		default:
			want = append([]byte{0xb9, byte(n >> 8), byte(n)}, p...)
		}
		if DedupKey(p) != keccak.Sum256(want) {
			t.Errorf("length %d", n)
		}
	}
}

func TestDecodeBlockShape(t *testing.T) {
	h := headerH(t)
	hb, _ := EncodeHeader(h)
	good := listOf2(hb, []byte{0xc0}, []byte{0xc0})
	b, err := DecodeBlock(good)
	if err != nil {
		t.Fatal(err)
	}
	if re, _ := EncodeBlock(b); !bytes.Equal(re, good) {
		t.Error("block re-encoding differs")
	}
	bad := [][]byte{
		listOf2(hb, []byte{0xc0}),                             // two items
		listOf2(hb, []byte{0x80}, []byte{0xc0}),               // transactions not a list
		listOf2(hb, []byte{0xc1, 0x05}, []byte{0xc0}),         // single-byte transaction
		listOf2(hb, []byte{0xc0}, []byte{0xc1, 0xc0}),         // uncle not a header
		listOf2(hb, []byte{0xc0}, []byte{0xc0}, []byte{0x80}), // withdrawals not a list
	}
	for i, b := range bad {
		if _, err := DecodeBlock(b); err == nil {
			t.Errorf("bad block %d decoded", i)
		}
	}
	typed := listOf2(hb, []byte{0xc3, 0x82, 0x02, 0xaa}, []byte{0xc0})
	if _, err := DecodeBlock(typed); err != nil {
		t.Errorf("typed transaction envelope: %v", err)
	}
}

// listOf2 builds a list of raw items with a long-form header when needed.
func listOf2(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	n := len(content)
	switch {
	case n < 56:
		return append([]byte{byte(0xc0 + n)}, content...)
	case n < 256:
		return append([]byte{0xf8, byte(n)}, content...)
	default:
		return append([]byte{0xf9, byte(n >> 8), byte(n)}, content...)
	}
}

func TestRandaoData(t *testing.T) {
	for _, c := range []struct {
		chain, number uint64
		want          string
	}{
		{8282, 0, "f6c98387ef170854e352073e846537b9947cfe23ddb4fa79932c3c248577ebd2"},
		{8282, 1, "48516c21b70c7a85c71e6fe34cd724419d7803fb58bc1cf3f69a76eb85d98b3f"},
		{8282, 256, "50ee1ee4f218972dbf488dd8f6eee54beb17e0b75169d1cdc543ac439516951c"},
		{8283, 1, "2536b43be46ffc0db54c300982998c0476b79a0c13bc5558e84887db975a046a"},
	} {
		got := RandaoData(new(big.Int).SetUint64(c.chain), types.HeightFromUint64(c.number))
		if hex.EncodeToString(got) != c.want {
			t.Errorf("randao_data(%d, %d) = %x", c.chain, c.number, got)
		}
	}
}

// The proposal digest covers EpochInfo, GasTip, RandaoReveal, PrevRound and
// the previous seals of the finalized header, and not Round, PreparedSeal or
// CommittedSeal.
//
// Covers: WBFT-HDR-041
func TestBlockHashCoverage(t *testing.T) {
	base := headerH(t)
	want := BlockHash(base)
	seal := &types.AggregatedSeal{Sealers: types.SealerSet{0x07}, Signature: bytes.Repeat([]byte{1}, 96)}
	with := func(f func(x *types.WBFTExtra)) *types.Header {
		h := base.Copy()
		x, err := DecodeExtra(h)
		if err != nil {
			t.Fatal(err)
		}
		f(x)
		if err := SetExtra(h, x); err != nil {
			t.Fatal(err)
		}
		return h
	}
	covered := map[string]func(x *types.WBFTExtra){
		"epoch info":         func(x *types.WBFTExtra) { x.EpochInfo = &types.EpochInfo{} },
		"gas tip":            func(x *types.WBFTExtra) { x.GasTip = big.NewInt(1) },
		"randao reveal":      func(x *types.WBFTExtra) { x.RandaoReveal = x.RandaoReveal[:64] },
		"prev round":         func(x *types.WBFTExtra) { x.PrevRound = 1 },
		"prev prepared seal": func(x *types.WBFTExtra) { x.PrevPreparedSeal = seal },
		"prev commit seal":   func(x *types.WBFTExtra) { x.PrevCommittedSeal = seal },
	}
	for name, f := range covered {
		if BlockHash(with(f)) == want {
			t.Errorf("%s does not change the digest", name)
		}
	}
	notCovered := map[string]func(x *types.WBFTExtra){
		"round":          func(x *types.WBFTExtra) { x.Round = 7 },
		"prepared seal":  func(x *types.WBFTExtra) { x.PreparedSeal = seal },
		"committed seal": func(x *types.WBFTExtra) { x.CommittedSeal = seal },
	}
	for name, f := range notCovered {
		if BlockHash(with(f)) != want {
			t.Errorf("%s changes the digest", name)
		}
	}
}
