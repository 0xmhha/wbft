package codec

import (
	"bytes"
	"testing"
)

// Decoders of external input must not panic, and every input a strict decoder
// accepts must re-encode to itself (A-03 §7 lists the exceptions, which are
// all ROUND-CHANGE forms; they are exercised by TestRoundChangeEdgeCases).

func FuzzDecodeExtra(f *testing.F) {
	for _, s := range []string{"ca808080c0c080c0c080c0", "cc808080c0c080c28080c080c0", "c3c0c0c0", ""} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		x, err := DecodeExtraBytes(b)
		if err != nil {
			return
		}
		re, err := EncodeExtra(x)
		if err != nil || !bytes.Equal(re, b) {
			t.Fatalf("re-encoding of %x is %x (%v)", b, re, err)
		}
	})
}

func FuzzDecodeHeader(f *testing.F) {
	h := headerH(f)
	enc, _ := EncodeHeader(h)
	f.Add(enc)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeader(b)
		if err != nil {
			return
		}
		re, err := EncodeHeader(h)
		if err != nil || !bytes.Equal(re, b) {
			t.Fatalf("re-encoding of %x is %x (%v)", b, re, err)
		}
		_ = BlockHash(h)
	})
}

func FuzzDecodeMessage(f *testing.F) {
	for _, s := range []string{"c9c6c30201c081aac0c0", "c9c5c30280c080c2c0c0", "c0"} {
		for _, code := range []uint8{0x12, 0x13, 0x14, 0x15} {
			f.Add(code, unhex(f, s))
		}
	}
	f.Fuzz(func(t *testing.T, code uint8, b []byte) {
		m, err := DecodeMessage(Code(code), b)
		if err != nil {
			return
		}
		re, err := EncodeMessage(m)
		if err != nil {
			t.Fatalf("encoding a decoded message: %v", err)
		}
		if (Code(code) == CodePrepare || Code(code) == CodeCommit) && !bytes.Equal(re, b) {
			t.Fatalf("re-encoding of %x is %x", b, re)
		}
		if _, err := SigningPayload(m, false, nil); err != nil {
			t.Fatalf("signing payload: %v", err)
		}
	})
}
