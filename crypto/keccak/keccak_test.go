package keccak

import (
	"encoding/hex"
	"testing"
)

func TestSum256(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		// A-02 §2 and §8.2.
		{nil, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{[]byte("wbft"), "154d94908e42308ff21897b1445bd5001dedb9fa41095ad342cb656fffe2c55f"},
		// keccak256(rlp([])), the empty uncle hash of A-01 §4.2.
		{[]byte{0xc0}, "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"},
	}
	for _, tt := range tests {
		got := Sum256(tt.in)
		if hex.EncodeToString(got[:]) != tt.want {
			t.Errorf("Sum256(%x) = %x, want %s", tt.in, got, tt.want)
		}
		if hex.EncodeToString(Sum256Bytes(tt.in)) != tt.want {
			t.Errorf("Sum256Bytes(%x) differs", tt.in)
		}
	}
	// Several arguments hash their concatenation.
	if Sum256([]byte("wb"), []byte("ft")) != Sum256([]byte("wbft")) {
		t.Error("Sum256 of parts differs from Sum256 of the concatenation")
	}
}
