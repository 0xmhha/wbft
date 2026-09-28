package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
)

// Header is the Ethereum block header as WBFT uses it. Number is a Height
// (arbitrary precision). The optional trailing fields are nil when absent;
// the header verification rejects every one of them except BaseFee.
//
// Encoding and hashing are done by package codec.
//
// Spec: WBFT-ENC-070
type Header struct {
	ParentHash  Hash
	UncleHash   Hash
	Coinbase    Address
	Root        Hash
	TxHash      Hash
	ReceiptHash Hash
	Bloom       Bloom
	Difficulty  *big.Int
	Number      Height
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   Hash
	Nonce       Nonce

	BaseFee          *big.Int // optional
	WithdrawalsHash  *Hash    // optional
	BlobGasUsed      *uint64  // optional
	ExcessBlobGas    *uint64  // optional
	ParentBeaconRoot *Hash    // optional
}

// Copy returns a deep copy of h.
func (h *Header) Copy() *Header {
	if h == nil {
		return nil
	}
	c := *h
	if h.Difficulty != nil {
		c.Difficulty = new(big.Int).Set(h.Difficulty)
	}
	if h.Extra != nil {
		c.Extra = append([]byte{}, h.Extra...)
	}
	if h.BaseFee != nil {
		c.BaseFee = new(big.Int).Set(h.BaseFee)
	}
	if h.WithdrawalsHash != nil {
		w := *h.WithdrawalsHash
		c.WithdrawalsHash = &w
	}
	if h.BlobGasUsed != nil {
		v := *h.BlobGasUsed
		c.BlobGasUsed = &v
	}
	if h.ExcessBlobGas != nil {
		v := *h.ExcessBlobGas
		c.ExcessBlobGas = &v
	}
	if h.ParentBeaconRoot != nil {
		r := *h.ParentBeaconRoot
		c.ParentBeaconRoot = &r
	}
	return &c
}

// ProposerOf returns the zero address for a header whose Number is 0 and the
// Coinbase otherwise: the "last proposer" input of proposer selection for the
// child of h.
//
// Spec: WBFT-PROP-002
func ProposerOf(h *Header) Address {
	if h == nil || h.Number.IsZero() {
		return Address{}
	}
	return h.Coinbase
}

// BodyRaw holds the RLP items of a block body after the header
// ([transactions, uncles] and, if present, withdrawals). wbft keeps them as
// received and does not interpret transactions.
type BodyRaw []rlp.RawValue

// Block is a header and the raw items of its body.
type Block struct {
	Header *Header
	Body   BodyRaw
}
