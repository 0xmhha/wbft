package kvstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/types"
)

// Tx sets Key to Value on behalf of From. Nonces of a sender start at 0 and
// increase by one per included transaction.
type Tx struct {
	From  types.Address
	Nonce uint64
	Key   string
	Value string
}

// Limits of a transaction.
const (
	MaxKey   = 256
	MaxValue = 64 << 10
)

// ErrTx reports a malformed transaction.
var ErrTx = errors.New("kvstore: malformed transaction")

// Encode returns the RLP encoding of the transaction.
func (t Tx) Encode() ([]byte, error) { return rlp.Encode(t) }

// DecodeTx decodes and checks the form of a transaction.
func DecodeTx(b []byte) (Tx, error) {
	var t Tx
	if err := rlp.DecodeStrict(b, &t); err != nil {
		return t, fmt.Errorf("%w: %v", ErrTx, err)
	}
	if t.Key == "" || len(t.Key) > MaxKey || len(t.Value) > MaxValue {
		return t, fmt.Errorf("%w: key or value size", ErrTx)
	}
	return t, nil
}

// TxKey is the identity of an encoded transaction.
func TxKey(b []byte) types.Hash { return keccak.Sum256(b) }

// admission is the mempool admission hook of an App.
type admission struct{ a *App }

var _ mempool.AdmissionHook = admission{}

func (admission) TxKey(tx []byte) (types.Hash, error) {
	if _, err := DecodeTx(tx); err != nil {
		return types.Hash{}, err
	}
	return TxKey(tx), nil
}

func (h admission) CheckTx(_ context.Context, req mempool.CheckRequest) mempool.CheckResponse {
	t, err := DecodeTx(req.Tx)
	if err != nil {
		return mempool.CheckResponse{Code: mempool.CodeReject, Reason: err.Error()}
	}
	state := h.a.headState().Nonce(t.From)
	if t.Nonce < state {
		return mempool.CheckResponse{Code: mempool.CodeReject, Reason: "nonce too low"}
	}
	return mempool.CheckResponse{Code: mempool.CodeOK, Meta: mempool.TxMeta{Sender: t.From, Nonce: t.Nonce, StateNonce: state,
		GasLimit: 1, Size: len(req.Tx)}}
}
