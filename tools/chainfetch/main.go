// Command chainfetch downloads blocks and receipts of a running network in
// their raw encodings, for development and replay tests.
//
// It calls debug_getRawBlock and debug_getRawReceipts for every block of the
// requested ranges, one request at a time and at most -rate requests per
// second, and writes
//
//	<out>/blocks/<number>.rlp    the RLP encoding of the block
//	<out>/receipts/<number>.rlp  an RLP list of the receipts' consensus encodings
//	<out>/manifest.json          network, client, ranges and range-end hashes
//
// Files that exist are kept, so an interrupted run continues where it
// stopped. Within each range the tool checks that every block's parent hash
// is the hash of the block before it, and that the hash of the last block
// equals the hash eth_getBlockByNumber reports.
//
// Usage (from the root of the wbft module):
//
//	go -C tools run ./chainfetch -rpc https://api.test.stablenet.network \
//	    -ranges 0-10000,14408300-14408700 -out ../data/stablenet-testnet
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "chainfetch:", err)
		os.Exit(1)
	}
}

// span is an inclusive block range.
type span struct{ From, To uint64 }

func parseRanges(s string) ([]span, error) {
	var out []span
	for _, part := range strings.Split(s, ",") {
		a, b, ok := strings.Cut(strings.TrimSpace(part), "-")
		from, err1 := strconv.ParseUint(a, 10, 64)
		to := from
		var err2 error
		if ok {
			to, err2 = strconv.ParseUint(b, 10, 64)
		}
		if err1 != nil || err2 != nil || to < from {
			return nil, fmt.Errorf("bad range %q", part)
		}
		out = append(out, span{from, to})
	}
	return out, nil
}

// manifest describes a download.
type manifest struct {
	RPC           string   `json:"rpc"`
	ChainID       string   `json:"chainId"`
	ClientVersion string   `json:"clientVersion"`
	FetchedAt     string   `json:"fetchedAt"`
	Ranges        []mrange `json:"ranges"`
	Genesis       string   `json:"genesisHash,omitempty"`
}

type mrange struct {
	From     uint64 `json:"from"`
	To       uint64 `json:"to"`
	LastHash string `json:"lastHash"`
	Txs      int    `json:"transactions"`
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("chainfetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rpcURL := fs.String("rpc", "https://api.test.stablenet.network", "JSON-RPC endpoint")
	rangesFlag := fs.String("ranges", "0-10000", "comma-separated inclusive block ranges")
	out := fs.String("out", "", "output directory")
	rate := fs.Float64("rate", 5, "requests per second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *rate <= 0 {
		return errors.New("-out is required and -rate must be positive")
	}
	ranges, err := parseRanges(*rangesFlag)
	if err != nil {
		return err
	}
	for _, d := range []string{"blocks", "receipts"} {
		if err := os.MkdirAll(filepath.Join(*out, d), 0o755); err != nil {
			return err
		}
	}
	c := &client{url: *rpcURL, http: &http.Client{Timeout: 30 * time.Second}, interval: time.Duration(float64(time.Second) / *rate)}
	m := manifest{RPC: *rpcURL, FetchedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := c.call(ctx, &m.ClientVersion, "web3_clientVersion"); err != nil {
		return err
	}
	if err := c.call(ctx, &m.ChainID, "eth_chainId"); err != nil {
		return err
	}
	for _, r := range ranges {
		mr, err := fetchRange(ctx, c, *out, r, stderr)
		if err != nil {
			return err
		}
		m.Ranges = append(m.Ranges, mr)
		if r.From == 0 {
			if b, err := readBlock(*out, 0); err == nil {
				m.Genesis = codec.BlockHash(b.Header).Hex()
			}
		}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "manifest.json"), append(raw, '\n'), 0o644)
}

func blockPath(dir string, n uint64) string {
	return filepath.Join(dir, "blocks", fmt.Sprintf("%012d.rlp", n))
}

func receiptsPath(dir string, n uint64) string {
	return filepath.Join(dir, "receipts", fmt.Sprintf("%012d.rlp", n))
}

func readBlock(dir string, n uint64) (*types.Block, error) {
	raw, err := os.ReadFile(blockPath(dir, n))
	if err != nil {
		return nil, err
	}
	return codec.DecodeBlock(raw)
}

// fetchRange downloads one range and checks its hash chain.
func fetchRange(ctx context.Context, c *client, dir string, r span, stderr io.Writer) (mrange, error) {
	mr := mrange{From: r.From, To: r.To}
	var prev types.Hash
	for n := r.From; n <= r.To; n++ {
		if err := fetchOne(ctx, c, dir, n); err != nil {
			return mr, fmt.Errorf("block %d: %w", n, err)
		}
		b, err := readBlock(dir, n)
		if err != nil {
			return mr, fmt.Errorf("block %d: %w", n, err)
		}
		if n > r.From && b.Header.ParentHash != prev {
			return mr, fmt.Errorf("block %d: parent hash %x is not the hash of block %d", n, b.Header.ParentHash, n-1)
		}
		prev = codec.BlockHash(b.Header)
		if items, err := rlp.ListItems(b.Body[0]); err == nil {
			mr.Txs += len(items)
		}
		if (n-r.From)%1000 == 0 {
			fmt.Fprintf(stderr, "chainfetch: block %d\n", n)
		}
	}
	var h struct {
		Hash string `json:"hash"`
	}
	if err := c.call(ctx, &h, "eth_getBlockByNumber", "0x"+strconv.FormatUint(r.To, 16), false); err != nil {
		return mr, err
	}
	if !strings.EqualFold(h.Hash, prev.Hex()) {
		return mr, fmt.Errorf("block %d: computed hash %s, node reports %s", r.To, prev.Hex(), h.Hash)
	}
	mr.LastHash = prev.Hex()
	return mr, nil
}

// fetchOne downloads the block and the receipts of number n unless both
// files exist.
func fetchOne(ctx context.Context, c *client, dir string, n uint64) error {
	bp, rp := blockPath(dir, n), receiptsPath(dir, n)
	_, errB := os.Stat(bp)
	_, errR := os.Stat(rp)
	if errB == nil && errR == nil {
		return nil
	}
	num := "0x" + strconv.FormatUint(n, 16)
	var blockHex string
	if err := c.call(ctx, &blockHex, "debug_getRawBlock", num); err != nil {
		return err
	}
	block, err := decodeHex(blockHex)
	if err != nil {
		return err
	}
	var receiptHex []string
	if err := c.call(ctx, &receiptHex, "debug_getRawReceipts", num); err != nil {
		return err
	}
	items := make([][]byte, len(receiptHex))
	for i, s := range receiptHex {
		b, err := decodeHex(s)
		if err != nil {
			return err
		}
		items[i] = rlp.EncodeString(b)
	}
	if err := writeAtomic(bp, block); err != nil {
		return err
	}
	return writeAtomic(rp, rlp.EncodeList(items...))
}

func decodeHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("missing 0x prefix")
	}
	return hex.DecodeString(s[2:])
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// client is a sequential JSON-RPC client with a request interval.
type client struct {
	url      string
	http     *http.Client
	interval time.Duration
	last     time.Time
	id       int
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// call sends one request; transport failures are retried three times.
func (c *client) call(ctx context.Context, out any, method string, params ...any) error {
	var err error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		var rerr *rpcError
		if err = c.callOnce(ctx, out, method, params); err == nil || errors.As(err, &rerr) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (c *client) callOnce(ctx context.Context, out any, method string, params []any) error {
	if d := time.Until(c.last.Add(c.interval)); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	c.last = time.Now()
	c.id++
	if params == nil {
		params = []any{}
	}
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
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
