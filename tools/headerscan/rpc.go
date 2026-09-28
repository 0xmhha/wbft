package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xmhha/wbft/types"
)

// limiter spaces requests at least interval apart. The scanner sends one
// request at a time, so this bounds the request rate.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func newLimiter(interval time.Duration) *limiter {
	return &limiter{interval: interval, now: time.Now, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// wait blocks until the next request may be sent.
func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if d := l.next.Sub(now); d > 0 {
		if err := l.sleep(ctx, d); err != nil {
			return err
		}
		now = l.next
	}
	l.next = now.Add(l.interval)
	return nil
}

// client is a sequential JSON-RPC client.
type client struct {
	url      string
	http     *http.Client
	lim      *limiter
	id       int
	requests int
	retries  int
}

func newClient(url string, lim *limiter) *client {
	return &client{url: url, http: &http.Client{Timeout: 30 * time.Second}, lim: lim, retries: 3}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// call sends one request and decodes its result into out. A transport
// failure is retried (each attempt waits for the limiter); an error answer
// of the node is not.
func (c *client) call(ctx context.Context, out any, method string, params ...any) error {
	var err error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			if serr := sleepCtx(ctx, time.Duration(attempt)*time.Second); serr != nil {
				return serr
			}
		}
		var rerr *rpcError
		err = c.callOnce(ctx, out, method, params)
		if err == nil || errors.As(err, &rerr) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (c *client) callOnce(ctx context.Context, out any, method string, params []any) error {
	if err := c.lim.wait(ctx); err != nil {
		return err
	}
	c.id++
	c.requests++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", method, resp.Status)
	}
	var msg struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if msg.Error != nil {
		return msg.Error
	}
	return json.Unmarshal(msg.Result, out)
}

// rpcHeader is the header part of an eth_getBlockByNumber answer.
type rpcHeader struct {
	Hash             string  `json:"hash"`
	ParentHash       string  `json:"parentHash"`
	UncleHash        string  `json:"sha3Uncles"`
	Coinbase         string  `json:"miner"`
	Root             string  `json:"stateRoot"`
	TxHash           string  `json:"transactionsRoot"`
	ReceiptHash      string  `json:"receiptsRoot"`
	Bloom            string  `json:"logsBloom"`
	Difficulty       string  `json:"difficulty"`
	Number           string  `json:"number"`
	GasLimit         string  `json:"gasLimit"`
	GasUsed          string  `json:"gasUsed"`
	Time             string  `json:"timestamp"`
	Extra            string  `json:"extraData"`
	MixDigest        string  `json:"mixHash"`
	Nonce            string  `json:"nonce"`
	BaseFee          *string `json:"baseFeePerGas"`
	WithdrawalsHash  *string `json:"withdrawalsRoot"`
	BlobGasUsed      *string `json:"blobGasUsed"`
	ExcessBlobGas    *string `json:"excessBlobGas"`
	ParentBeaconRoot *string `json:"parentBeaconBlockRoot"`
}

func decodeHex(field, s string, size int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%s: missing 0x prefix", field)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if size >= 0 && len(b) != size {
		return nil, fmt.Errorf("%s: %d bytes, want %d", field, len(b), size)
	}
	return b, nil
}

func decodeQuantity(field, s string) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 {
		return nil, fmt.Errorf("%s: bad quantity %q", field, s)
	}
	v, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, fmt.Errorf("%s: bad quantity %q", field, s)
	}
	return v, nil
}

func decodeUint64(field, s string) (uint64, error) {
	if !strings.HasPrefix(s, "0x") {
		return 0, fmt.Errorf("%s: bad quantity %q", field, s)
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return v, nil
}

// toHeader converts the JSON header to the wbft header type. It returns the
// hash the node reported as well.
func (r *rpcHeader) toHeader() (*types.Header, types.Hash, error) {
	var h types.Header
	var err error
	fixed := []struct {
		field string
		src   string
		dst   []byte
	}{
		{"hash", r.Hash, nil},
		{"parentHash", r.ParentHash, h.ParentHash[:]},
		{"sha3Uncles", r.UncleHash, h.UncleHash[:]},
		{"miner", r.Coinbase, h.Coinbase[:]},
		{"stateRoot", r.Root, h.Root[:]},
		{"transactionsRoot", r.TxHash, h.TxHash[:]},
		{"receiptsRoot", r.ReceiptHash, h.ReceiptHash[:]},
		{"logsBloom", r.Bloom, h.Bloom[:]},
		{"mixHash", r.MixDigest, h.MixDigest[:]},
		{"nonce", r.Nonce, h.Nonce[:]},
	}
	var reported types.Hash
	fixed[0].dst = reported[:]
	for _, f := range fixed {
		b, err := decodeHex(f.field, f.src, len(f.dst))
		if err != nil {
			return nil, types.Hash{}, err
		}
		copy(f.dst, b)
	}
	if h.Difficulty, err = decodeQuantity("difficulty", r.Difficulty); err != nil {
		return nil, types.Hash{}, err
	}
	n, err := decodeQuantity("number", r.Number)
	if err != nil {
		return nil, types.Hash{}, err
	}
	if h.Number, err = types.HeightFromBig(n); err != nil {
		return nil, types.Hash{}, err
	}
	if h.GasLimit, err = decodeUint64("gasLimit", r.GasLimit); err != nil {
		return nil, types.Hash{}, err
	}
	if h.GasUsed, err = decodeUint64("gasUsed", r.GasUsed); err != nil {
		return nil, types.Hash{}, err
	}
	if h.Time, err = decodeUint64("timestamp", r.Time); err != nil {
		return nil, types.Hash{}, err
	}
	if h.Extra, err = decodeHex("extraData", r.Extra, -1); err != nil {
		return nil, types.Hash{}, err
	}
	if r.BaseFee != nil {
		if h.BaseFee, err = decodeQuantity("baseFeePerGas", *r.BaseFee); err != nil {
			return nil, types.Hash{}, err
		}
	}
	optHash := func(field string, s *string) (*types.Hash, error) {
		if s == nil {
			return nil, nil
		}
		b, err := decodeHex(field, *s, 32)
		if err != nil {
			return nil, err
		}
		var v types.Hash
		copy(v[:], b)
		return &v, nil
	}
	optU64 := func(field string, s *string) (*uint64, error) {
		if s == nil {
			return nil, nil
		}
		v, err := decodeUint64(field, *s)
		return &v, err
	}
	if h.WithdrawalsHash, err = optHash("withdrawalsRoot", r.WithdrawalsHash); err != nil {
		return nil, types.Hash{}, err
	}
	if h.ParentBeaconRoot, err = optHash("parentBeaconBlockRoot", r.ParentBeaconRoot); err != nil {
		return nil, types.Hash{}, err
	}
	if h.BlobGasUsed, err = optU64("blobGasUsed", r.BlobGasUsed); err != nil {
		return nil, types.Hash{}, err
	}
	if h.ExcessBlobGas, err = optU64("excessBlobGas", r.ExcessBlobGas); err != nil {
		return nil, types.Hash{}, err
	}
	return &h, reported, nil
}

// errNotFound is a block the node does not have (a null result).
var errNotFound = errors.New("block not found")

func (c *client) headerByNumber(ctx context.Context, n uint64) (*types.Header, types.Hash, error) {
	var r *rpcHeader
	if err := c.call(ctx, &r, "eth_getBlockByNumber", "0x"+strconv.FormatUint(n, 16), false); err != nil {
		return nil, types.Hash{}, fmt.Errorf("block %d: %w", n, err)
	}
	if r == nil {
		return nil, types.Hash{}, fmt.Errorf("block %d: %w", n, errNotFound)
	}
	h, hash, err := r.toHeader()
	if err != nil {
		return nil, types.Hash{}, fmt.Errorf("block %d: %w", n, err)
	}
	return h, hash, nil
}

func (c *client) headerByHash(ctx context.Context, hash types.Hash) (*types.Header, types.Hash, error) {
	var r *rpcHeader
	if err := c.call(ctx, &r, "eth_getBlockByHash", hash.Hex(), false); err != nil {
		return nil, types.Hash{}, fmt.Errorf("block %s: %w", hash.Hex(), err)
	}
	if r == nil {
		return nil, types.Hash{}, fmt.Errorf("block %s: %w", hash.Hex(), errNotFound)
	}
	h, got, err := r.toHeader()
	if err != nil {
		return nil, types.Hash{}, fmt.Errorf("block %s: %w", hash.Hex(), err)
	}
	return h, got, nil
}

func (c *client) chainID(ctx context.Context) (*big.Int, error) {
	var s string
	if err := c.call(ctx, &s, "eth_chainId"); err != nil {
		return nil, err
	}
	return decodeQuantity("chainId", s)
}

func (c *client) blockNumber(ctx context.Context) (uint64, error) {
	var s string
	if err := c.call(ctx, &s, "eth_blockNumber"); err != nil {
		return 0, err
	}
	return decodeUint64("blockNumber", s)
}
