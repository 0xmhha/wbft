package journal

import (
	"bytes"
	"testing"
)

func TestRecordedPolicyConfiguration(t *testing.T) {
	for _, profile := range []string{"", CheckedProposerPolicyProfile, "future"} {
		for _, raw := range [][]byte{
			[]byte(`{"anzeon":{"wbft":{}}}`),
			[]byte(`{"anzeon":{"wbft":{"proposerPolicy":2}}}`),
		} {
			options := CoreOptions{ChainConfig: raw, ProposerPolicyProfile: profile}
			encoded, err := encodeBody(Record{Body: &SegmentRec{Identity: Identity{Core: options}}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			record, err := decodeBody(KindSegment, encoded)
			if err != nil {
				t.Fatal(err)
			}
			got := record.Body.(*SegmentRec).Core
			if !bytes.Equal(raw, got.ChainConfig) || got.ProposerPolicyProfile != profile {
				t.Fatal("recorded source or profile changed")
			}
			cfg, err := got.Configuration()
			if profile == "future" || profile == CheckedProposerPolicyProfile && bytes.Contains(raw, []byte(`:2`)) {
				if err == nil {
					t.Fatal("unsupported policy or profile accepted")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if profile == "" && !bytes.Contains(raw, []byte(`:2`)) && cfg.Base().ProposerPolicy != nil {
				t.Fatal("legacy source acquired a new default")
			}
			if profile == CheckedProposerPolicyProfile && (cfg.Base().ProposerPolicy == nil || cfg.Base().ProposerPolicy.ID != 0) {
				t.Fatal("recorded default absent")
			}
		}
	}
}
