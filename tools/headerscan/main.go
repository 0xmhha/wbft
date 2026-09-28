// Command headerscan checks the headers of a running StableNet network with
// the header rules of wbft.
//
// It fetches headers over JSON-RPC (eth_getBlockByNumber), one request at a
// time and at most -rate requests per second, and verifies every header of
// the scanned ranges twice:
//
//   - header.VerifyHeader in HeaderOnly mode with seal checks: the steps that
//     need the state of the parent (H15b, H21) are skipped because the
//     scanner has no authority snapshots;
//   - header.VerifyLight with the validator sets taken from the fetched epoch
//     headers.
//
// The execution-side steps (H3, H5 .. H9, H13, H14) run through the StableNet
// preset stand-in of internal/snetpartb. It also checks that the block hash
// computed by wbft equals the hash the node reports.
//
// The scanned ranges are the first -span+1 blocks from genesis and, for every
// fork block F > 0 of the preset, the blocks F .. F+span. Ranges are clipped
// to the current head.
//
// Usage (from the root of the wbft module):
//
//	go -C tools run ./headerscan -rpc https://api.test.stablenet.network
//
// The built-in preset is the StableNet testnet (chain ID 8283). For another
// network give its genesis "config" object with -config and its fork blocks
// with -forks. Every rejection is printed with the block number, hash, step
// and error. The exit status is 0 when every header is accepted, 1 when a
// header is rejected, and 2 on a usage, network or decoding error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/internal/snetpartb"
	"github.com/0xmhha/wbft/types"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("headerscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rpcURL := fs.String("rpc", defaultRPC, "JSON-RPC endpoint of a node of the network")
	configFile := fs.String("config", "", "genesis \"config\" object of the network (default: the built-in testnet preset)")
	forksFlag := fs.String("forks", "", "comma-separated fork blocks to scan from (default: the forks of the built-in preset)")
	genesisHash := fs.String("genesis-hash", "", "expected genesis hash (default: that of the built-in preset; \"-\" skips the check)")
	span := fs.Uint64("span", 100, "number of blocks after genesis and after every fork block")
	rate := fs.Float64("rate", 5, "maximum requests per second")
	verbose := fs.Bool("v", false, "print every verified block")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "headerscan: %v\n", err)
		return 2
	}
	if *rate <= 0 || *rate > 5 {
		return fail(fmt.Errorf("-rate must be in (0, 5]"))
	}

	p := testnetPreset
	if *configFile != "" {
		raw, err := os.ReadFile(*configFile)
		if err != nil {
			return fail(err)
		}
		p = preset{config: string(raw), london: big.NewInt(0)}
	}
	cfg, err := types.ParseChainConfig([]byte(p.config))
	if err != nil {
		return fail(err)
	}
	forks := p.forks
	if *forksFlag != "" {
		if forks, err = parseForks(*forksFlag); err != nil {
			return fail(err)
		}
	}
	wantGenesis := p.genesisHash
	if *genesisHash != "" {
		wantGenesis = *genesisHash
	}
	if wantGenesis == "-" {
		wantGenesis = ""
	}

	client := newClient(*rpcURL, newLimiter(time.Duration(float64(time.Second) / *rate)))
	s := &scanner{
		cfg:     cfg,
		partB:   &snetpartb.PartB{Forks: snetpartb.Forks{London: p.london}},
		chain:   newRPCChain(ctx, client),
		out:     stdout,
		verbose: *verbose,
		now:     time.Now,
	}
	res, err := s.scan(ctx, client, forks, *span, wantGenesis)
	fmt.Fprintf(stdout, "headerscan: %s\n", res.summary())
	if err != nil {
		return fail(err)
	}
	if res.rejected() {
		return 1
	}
	return 0
}

func parseForks(s string) ([]uint64, error) {
	var out []uint64
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(strings.ReplaceAll(f, "_", ""))
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("fork block %q: %w", f, err)
		}
		out = append(out, n)
	}
	return out, nil
}
