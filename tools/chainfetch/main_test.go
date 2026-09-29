package main

import "testing"

func TestParseRanges(t *testing.T) {
	got, err := parseRanges("0-10000, 14408300-14408700,5")
	if err != nil {
		t.Fatal(err)
	}
	want := []span{{0, 10000}, {14408300, 14408700}, {5, 5}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v, want %v", got, want)
		}
	}
	for _, bad := range []string{"", "5-3", "a-b", "1-"} {
		if _, err := parseRanges(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
