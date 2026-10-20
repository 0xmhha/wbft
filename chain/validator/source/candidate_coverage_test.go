package source

import (
	"github.com/0xmhha/wbft/types"
	"github.com/holiman/uint256"
	"testing"
)

func TestCandidateInputCoverageAndCopies(t *testing.T) {
	for _, entries := range [][]types.CandidateEntry{nil, {}, {{Addr: types.Address{1}, BLSPublicKey: []byte{2}}}} {
		snapshot, err := NewAuthoritySnapshot(types.HeightFromUint64(3), types.Hash{4}, uint256.NewInt(0), nil, nil, entries)
		if err != nil || snapshot.HasCandidates() != (entries != nil) {
			t.Fatal("candidate coverage", err)
		}
		if len(entries) > 0 {
			entries[0].Addr[0] = 9
			entries[0].BLSPublicKey[0] = 9
			copied := snapshot.Candidates()
			copied[0].Addr[0] = 8
			copied[0].BLSPublicKey[0] = 8
			if snapshot.Candidates()[0].Addr[0] != 1 || snapshot.Candidates()[0].BLSPublicKey[0] != 2 {
				t.Fatal("candidate input aliases a caller")
			}
		}
	}
}
