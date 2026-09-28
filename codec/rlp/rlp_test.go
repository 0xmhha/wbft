package rlp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func raws(items []RawValue) [][]byte {
	out := make([][]byte, len(items))
	for i, it := range items {
		out[i] = it
	}
	return out
}

// isDecodeErr reports whether err is wrapped exactly once in *ErrDecode.
func isDecodeErr(err error) bool {
	var d *ErrDecode
	if !errors.As(err, &d) {
		return false
	}
	var inner *ErrDecode
	return !errors.As(d.Err, &inner)
}

func TestEmptyValues(t *testing.T) {
	if !bytes.Equal(EmptyString, EncodeString(nil)) || !bytes.Equal(EmptyList, EncodeList()) {
		t.Errorf("EmptyString %x, EncodeString(nil) %x, EmptyList %x, EncodeList() %x",
			EmptyString, EncodeString(nil), EmptyList, EncodeList())
	}
}

func TestDecodeStrict(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		var u uint64
		for _, tt := range []struct {
			in   string
			want uint64
		}{
			{"80", 0}, {"01", 1}, {"7f", 0x7f}, {"8180", 0x80}, {"820100", 0x100},
			{"88ffffffffffffffff", 1<<64 - 1},
		} {
			if err := DecodeStrict(unhex(t, tt.in), &u); err != nil || u != tt.want {
				t.Errorf("uint %s: %d, %v; want %d", tt.in, u, err, tt.want)
			}
		}
		var b []byte
		if err := DecodeStrict(unhex(t, "83646f67"), &b); err != nil || string(b) != "dog" {
			t.Errorf("string: %q, %v", b, err)
		}
		long := "b838" + strings.Repeat("61", 56)
		if err := DecodeStrict(unhex(t, long), &b); err != nil || len(b) != 56 {
			t.Errorf("56-byte string: %d bytes, %v", len(b), err)
		}
		var l []uint64
		if err := DecodeStrict(unhex(t, "c3010203"), &l); err != nil || len(l) != 3 || l[2] != 3 {
			t.Errorf("list: %v, %v", l, err)
		}
		var n big.Int
		if err := DecodeStrict(unhex(t, "8a010000000000000000ff"), &n); err != nil || n.Text(16) != "10000000000000000ff" {
			t.Errorf("big: %s, %v", n.Text(16), err)
		}
	})
	t.Run("reject", func(t *testing.T) {
		for _, tt := range []struct {
			name, in string
		}{
			{"single byte below 0x80 as a string", "8105"},
			{"long form for a length below 56", "b80161"},
			{"leading zero in a length", "b90038" + strings.Repeat("61", 56)},
			{"leading zero in an integer", "820001"},
			{"bytes after the value", "0505"},
			{"list for an integer", "c0"},
			{"size past the end", "8301"},
			{"empty input", ""},
			{"integer above 64 bits", "89010000000000000000"},
		} {
			var u uint64
			err := DecodeStrict(unhex(t, tt.in), &u)
			if err == nil || !isDecodeErr(err) {
				t.Errorf("%s (%s): err %v", tt.name, tt.in, err)
			}
		}
		var l []uint64
		if err := DecodeStrict(unhex(t, "c20102ff"), &l); !isDecodeErr(err) {
			t.Errorf("list with trailing byte: %v", err)
		}
	})
}

func TestEncode(t *testing.T) {
	for _, tt := range []struct {
		v    any
		want string
	}{
		{uint64(0), "80"},
		{uint64(0x7f), "7f"},
		{uint64(0x80), "8180"},
		{uint64(0x400), "820400"},
		{[]byte{}, "80"},
		{"dog", "83646f67"},
		{[]uint64{}, "c0"},
		{[]any{uint64(1), []byte("ab"), []uint64{}}, "c501826162c0"},
		{big.NewInt(0), "80"},
	} {
		got, err := Encode(tt.v)
		if err != nil || hex.EncodeToString(got) != tt.want {
			t.Errorf("Encode(%v) = %x, %v; want %s", tt.v, got, err, tt.want)
		}
	}
	if _, err := Encode(big.NewInt(-1)); err == nil {
		t.Error("negative big.Int encoded")
	}
	if _, err := Encode(make(chan int)); err == nil {
		t.Error("channel encoded")
	}
}

func TestSplitList(t *testing.T) {
	content, rest, err := SplitList(unhex(t, "c3010203ff"))
	if err != nil || hex.EncodeToString(content) != "010203" || hex.EncodeToString(rest) != "ff" {
		t.Errorf("content %x rest %x err %v", content, rest, err)
	}
	content, rest, err = SplitList(EmptyList)
	if err != nil || len(content) != 0 || len(rest) != 0 {
		t.Errorf("empty list: %x %x %v", content, rest, err)
	}
	for _, in := range []string{"", "80", "05", "c30102", "f80101"} {
		if _, _, err := SplitList(unhex(t, in)); !isDecodeErr(err) {
			t.Errorf("SplitList(%s): %v", in, err)
		}
	}
}

func TestItems(t *testing.T) {
	items, err := Items(unhex(t, "01826162c0c20304"))
	want := []string{"01", "826162", "c0", "c20304"}
	if err != nil || len(items) != len(want) {
		t.Fatalf("items %x err %v", items, err)
	}
	for i, it := range items {
		if hex.EncodeToString(it) != want[i] {
			t.Errorf("item %d = %x, want %s", i, it, want[i])
		}
	}
	if items, err := Items(nil); err != nil || len(items) != 0 {
		t.Errorf("empty content: %v %v", items, err)
	}
	for _, in := range []string{"018301", "8105", "b80161", "c3"} {
		if _, err := Items(unhex(t, in)); !isDecodeErr(err) {
			t.Errorf("Items(%s): %v", in, err)
		}
	}
}

func TestListItems(t *testing.T) {
	items, err := ListItems(unhex(t, "c3010203"))
	if err != nil || len(items) != 3 || hex.EncodeToString(items[1]) != "02" {
		t.Errorf("items %x err %v", items, err)
	}
	if items, err := ListItems(EmptyList); err != nil || len(items) != 0 {
		t.Errorf("empty list: %v %v", items, err)
	}
	for _, in := range []string{"c0c0", "80", "c28105", "c30102", ""} {
		if _, err := ListItems(unhex(t, in)); !isDecodeErr(err) {
			t.Errorf("ListItems(%s): %v", in, err)
		}
	}
}

func TestEncodeString(t *testing.T) {
	for _, tt := range []struct {
		in, want string
	}{
		{"", "80"},
		{"00", "00"},
		{"7f", "7f"},
		{"80", "8180"},
		{"0102", "820102"},
		{strings.Repeat("aa", 55), "b7" + strings.Repeat("aa", 55)},
		{strings.Repeat("aa", 56), "b838" + strings.Repeat("aa", 56)},
		{strings.Repeat("aa", 256), "b90100" + strings.Repeat("aa", 256)},
	} {
		if got := EncodeString(unhex(t, tt.in)); hex.EncodeToString(got) != tt.want {
			t.Errorf("EncodeString(%s) = %x", tt.in, got)
		}
	}
}

func TestEncodeList(t *testing.T) {
	// Items are copied verbatim.
	got := EncodeList(unhex(t, "01"), unhex(t, "826162"), EmptyList)
	if hex.EncodeToString(got) != "c501826162c0" {
		t.Errorf("EncodeList = %x", got)
	}
	// A list of 56 content bytes takes the long form.
	items := make([][]byte, 28)
	for i := range items {
		items[i] = []byte{0x01, 0x02} // two single-byte items, copied as they are
	}
	got = EncodeList(items...)
	if !bytes.HasPrefix(got, unhex(t, "f838")) || len(got) != 58 {
		t.Errorf("long list header %x, length %d", got[:2], len(got))
	}
	// EncodeList and ListItems are inverse on canonical input.
	enc := EncodeList(EncodeString([]byte("dog")), EncodeList(EncodeString(nil)))
	back, err := ListItems(enc)
	if err != nil || len(back) != 2 || !bytes.Equal(EncodeList(raws(back)...), enc) {
		t.Errorf("round trip %x: %x %v", enc, back, err)
	}
}

func TestSplitString(t *testing.T) {
	for _, tt := range []struct {
		in, content, rest string
	}{
		{"05", "05", ""},
		{"05ff", "05", "ff"},
		{"80", "", ""},
		{"8180c0", "80", "c0"},
		{"83646f67", "646f67", ""},
		{"b838" + strings.Repeat("61", 56), strings.Repeat("61", 56), ""},
	} {
		content, rest, err := SplitString(unhex(t, tt.in))
		if err != nil || hex.EncodeToString(content) != tt.content || hex.EncodeToString(rest) != tt.rest {
			t.Errorf("SplitString(%s) = %x, %x, %v", tt.in, content, rest, err)
		}
	}
	for _, in := range []string{"", "c0", "c3010203", "8105", "b80161", "8301"} {
		if _, _, err := SplitString(unhex(t, in)); !isDecodeErr(err) {
			t.Errorf("SplitString(%s): %v", in, err)
		}
	}
}

func TestErrDecode(t *testing.T) {
	err := wrap(errors.New("x"))
	if err.Error() != "rlp decode: x" || errors.Unwrap(err).Error() != "x" {
		t.Errorf("message %q", err)
	}
	if wrap(err) != err {
		t.Error("an ErrDecode was wrapped twice")
	}
	if wrap(nil) != nil {
		t.Error("nil was wrapped")
	}
}

// Splitting and decoding never panic, and every input that a strict function
// accepts re-encodes to itself.
func FuzzRLP(f *testing.F) {
	for _, s := range []string{"", "80", "05", "8180", "8105", "c0", "c3010203", "c501826162c0",
		"b838" + strings.Repeat("61", 56), "f838" + strings.Repeat("0102", 28), "c20102ff"} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if items, err := ListItems(b); err == nil {
			if re := EncodeList(raws(items)...); !bytes.Equal(re, b) {
				t.Fatalf("ListItems(%x) re-encodes to %x", b, re)
			}
		} else if !isDecodeErr(err) {
			t.Fatalf("ListItems(%x): unwrapped error %v", b, err)
		}
		if content, rest, err := SplitString(b); err == nil {
			if re := append(EncodeString(content), rest...); !bytes.Equal(re, b) {
				t.Fatalf("SplitString(%x) re-encodes to %x", b, re)
			}
		}
		if content, rest, err := SplitList(b); err == nil {
			// The list header is canonical, so wrapping the content again
			// gives back the bytes before rest.
			if re := EncodeList(content); !bytes.Equal(re, b[:len(b)-len(rest)]) {
				t.Fatalf("SplitList(%x) re-encodes to %x", b, re)
			}
		}
		var raw []byte
		if err := DecodeStrict(b, &raw); err == nil {
			if re, err := Encode(raw); err != nil || !bytes.Equal(re, b) {
				t.Fatalf("DecodeStrict(%x) into []byte re-encodes to %x (%v)", b, re, err)
			}
		}
		var u uint64
		if err := DecodeStrict(b, &u); err == nil {
			if re, err := Encode(u); err != nil || !bytes.Equal(re, b) {
				t.Fatalf("DecodeStrict(%x) into uint64 re-encodes to %x (%v)", b, re, err)
			}
		}
		var n big.Int
		if err := DecodeStrict(b, &n); err == nil {
			if re, err := Encode(&n); err != nil || !bytes.Equal(re, b) {
				t.Fatalf("DecodeStrict(%x) into big.Int re-encodes to %x (%v)", b, re, err)
			}
		}
	})
}
