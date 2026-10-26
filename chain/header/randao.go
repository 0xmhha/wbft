package header

import (
	"fmt"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

// blsRandaoActive selects the rule from the independently checked parent.
func blsRandaoActive(cfg *types.Config, parent *types.Header) bool {
	return parent != nil && cfg.Rules(types.BLSRandao, parent.Number.AddUint64(1))
}

// verifyRandao never infers the active format from a signature's length.
func verifyRandao(cfg *types.Config, h, parent *types.Header, v *validator.Set, reveal []byte) error {
	if !blsRandaoActive(cfg, parent) {
		return ecdsa.CheckSigner(codec.RandaoData(cfg.ChainID, h.Number), reveal, h.Coinbase)
	}
	i, ok := v.IndexOf(h.Coinbase)
	if !ok {
		return fmt.Errorf("randao: proposer is not in the validator set")
	}
	pk, err := bls.DecodePublicKey(v.At(i).BLSPublicKey)
	if err != nil {
		return err
	}
	sig, err := bls.DecodeSignature(reveal)
	if err != nil {
		return err
	}
	if !bls.Verify(pk, codec.BLSRandaoData(cfg.ChainID, h.Number), sig) {
		return fmt.Errorf("randao: BLS signature does not match the registered proposer key")
	}
	return nil
}
