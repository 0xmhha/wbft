package codec

import (
	"errors"
	"math/big"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

// headerRLP is the go-ethereum header list. The trailing fields are optional:
// an absent one is omitted when no later one is present, and written as an
// empty string otherwise; a missing trailing field decodes as nil.
type headerRLP struct {
	ParentHash  types.Hash
	UncleHash   types.Hash
	Coinbase    types.Address
	Root        types.Hash
	TxHash      types.Hash
	ReceiptHash types.Hash
	Bloom       types.Bloom
	Difficulty  *big.Int
	Number      *big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   types.Hash
	Nonce       types.Nonce

	BaseFee          *big.Int    `rlp:"optional"`
	WithdrawalsHash  *types.Hash `rlp:"optional"`
	BlobGasUsed      *uint64     `rlp:"optional"`
	ExcessBlobGas    *uint64     `rlp:"optional"`
	ParentBeaconRoot *types.Hash `rlp:"optional"`
}

func headerToRLP(h *types.Header) *headerRLP {
	return &headerRLP{
		ParentHash:       h.ParentHash,
		UncleHash:        h.UncleHash,
		Coinbase:         h.Coinbase,
		Root:             h.Root,
		TxHash:           h.TxHash,
		ReceiptHash:      h.ReceiptHash,
		Bloom:            h.Bloom,
		Difficulty:       h.Difficulty,
		Number:           h.Number.Big(),
		GasLimit:         h.GasLimit,
		GasUsed:          h.GasUsed,
		Time:             h.Time,
		Extra:            h.Extra,
		MixDigest:        h.MixDigest,
		Nonce:            h.Nonce,
		BaseFee:          h.BaseFee,
		WithdrawalsHash:  h.WithdrawalsHash,
		BlobGasUsed:      h.BlobGasUsed,
		ExcessBlobGas:    h.ExcessBlobGas,
		ParentBeaconRoot: h.ParentBeaconRoot,
	}
}

func headerFromRLP(w *headerRLP) *types.Header {
	return &types.Header{
		ParentHash:       w.ParentHash,
		UncleHash:        w.UncleHash,
		Coinbase:         w.Coinbase,
		Root:             w.Root,
		TxHash:           w.TxHash,
		ReceiptHash:      w.ReceiptHash,
		Bloom:            w.Bloom,
		Difficulty:       w.Difficulty,
		Number:           types.MustHeightFromBig(w.Number), // decoded integers are never negative
		GasLimit:         w.GasLimit,
		GasUsed:          w.GasUsed,
		Time:             w.Time,
		Extra:            w.Extra,
		MixDigest:        w.MixDigest,
		Nonce:            w.Nonce,
		BaseFee:          w.BaseFee,
		WithdrawalsHash:  w.WithdrawalsHash,
		BlobGasUsed:      w.BlobGasUsed,
		ExcessBlobGas:    w.ExcessBlobGas,
		ParentBeaconRoot: w.ParentBeaconRoot,
	}
}

// EncodeHeader returns the RLP encoding of h: the fifteen mandatory items and
// the optional items up to the last present one.
//
// Spec: WBFT-ENC-070
func EncodeHeader(h *types.Header) ([]byte, error) {
	return rlp.Encode(headerToRLP(h))
}

// DecodeHeader decodes b as exactly one header list.
//
// Spec: WBFT-ENC-070
func DecodeHeader(b []byte) (*types.Header, error) {
	var w headerRLP
	if err := rlp.DecodeStrict(b, &w); err != nil {
		return nil, err
	}
	return headerFromRLP(&w), nil
}

// withdrawalRLP is one element of the optional withdrawals list of a block.
type withdrawalRLP struct {
	Index     uint64
	Validator uint64
	Address   types.Address
	Amount    uint64
}

// ErrInvalidBlock is returned when a block does not have the shape of the
// go-ethereum block list.
var ErrInvalidBlock = errors.New("invalid block encoding")

// EncodeBlock returns the RLP encoding of b: the header followed by the raw
// body items.
//
// Spec: WBFT-ENC-071
func EncodeBlock(b *types.Block) ([]byte, error) {
	hb, err := EncodeHeader(b.Header)
	if err != nil {
		return nil, err
	}
	items := make([][]byte, 0, 1+len(b.Body))
	items = append(items, hb)
	for _, it := range b.Body {
		items = append(items, it)
	}
	return rlp.EncodeList(items...), nil
}

// DecodeBlock decodes b as exactly one block list [header, transactions,
// uncles] or [header, transactions, uncles, withdrawals]. The body items are
// kept as received; the shape checks are those the go-ethereum block decoder
// applies before transaction contents: transactions is a list whose elements
// are lists or strings of at least two bytes, every uncle is a header, and
// every withdrawal is a four-item list.
//
// Spec: WBFT-ENC-071
func DecodeBlock(b []byte) (*types.Block, error) {
	items, err := rlp.ListItems(b)
	if err != nil {
		return nil, err
	}
	return blockFromItems(items)
}

func blockFromItems(items []rlp.RawValue) (*types.Block, error) {
	if len(items) != 3 && len(items) != 4 {
		return nil, &rlp.ErrDecode{Err: ErrInvalidBlock}
	}
	h, err := DecodeHeader(items[0])
	if err != nil {
		return nil, err
	}
	txs, err := rlp.ListItems(items[1])
	if err != nil {
		return nil, err
	}
	for _, tx := range txs {
		if err := checkTransactionItem(tx); err != nil {
			return nil, err
		}
	}
	uncles, err := rlp.ListItems(items[2])
	if err != nil {
		return nil, err
	}
	for _, u := range uncles {
		if _, err := DecodeHeader(u); err != nil {
			return nil, err
		}
	}
	if len(items) == 4 {
		var ws []withdrawalRLP
		if err := rlp.DecodeStrict(items[3], &ws); err != nil {
			return nil, err
		}
	}
	body := make(types.BodyRaw, len(items)-1)
	for i, it := range items[1:] {
		body[i] = append(rlp.RawValue(nil), it...)
	}
	return &types.Block{Header: h, Body: body}, nil
}

// checkTransactionItem accepts a legacy transaction (a list) or a typed
// transaction envelope (a string of at least a type byte and a payload).
func checkTransactionItem(it rlp.RawValue) error {
	if len(it) == 0 {
		return &rlp.ErrDecode{Err: ErrInvalidBlock}
	}
	switch {
	case it[0] >= 0xc0:
		return nil
	case it[0] < 0x80:
		// a single byte: too short for a typed transaction
		return &rlp.ErrDecode{Err: ErrInvalidBlock}
	default:
		var payload []byte
		if err := rlp.DecodeStrict(it, &payload); err != nil {
			return err
		}
		if len(payload) <= 1 {
			return &rlp.ErrDecode{Err: ErrInvalidBlock}
		}
		return nil
	}
}
