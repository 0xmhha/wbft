// Command wbft-kvstore runs the kvstore example application on the wbft
// consensus layer, for local development networks.
//
//	wbft-kvstore init -dir ./devnet -nodes 4
//	wbft-kvstore start -home ./devnet/node0
//
// init writes one directory per node with a node key, the shared genesis
// and a node.json that lists the peers on 127.0.0.1. start runs one node
// and serves an HTTP API:
//
//	POST /tx           {"from":"0x..","nonce":0,"key":"k","value":"v"}
//	GET  /kv/{key}     the value in the head state
//	GET  /nonce/{addr} the next nonce of a sender
//	GET  /status       the head
//	POST /rpc          JSON-RPC: wbft_nodeInfo, wbft_consensusState, wbft_peers
//
// Transactions are not signed and the transport is not authenticated: this
// is a development tool, not a network to deploy.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/examples/kvstore"
	"github.com/0xmhha/wbft/mempool"
	"github.com/0xmhha/wbft/p2p/devnet"
	"github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

// nodeFile is the node.json of a node directory.
type nodeFile struct {
	Self    types.Address `json:"self"`
	Listen  string        `json:"listen"`
	HTTP    string        `json:"http"`
	Network string        `json:"network"`
	Peers   []peerFile    `json:"peers"`
}

type peerFile struct {
	Addr     types.Address `json:"addr"`
	Endpoint string        `json:"endpoint"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCmd(os.Args[2:])
	case "start":
		err = startCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wbft-kvstore:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wbft-kvstore init -dir DIR -nodes N | start -home DIR")
	os.Exit(2)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "./devnet", "output directory")
	nodes := fs.Int("nodes", 4, "number of validators")
	p2pBase := fs.Int("p2p-port", 26650, "transport port of node 0; node i uses port + i")
	httpBase := fs.Int("http-port", 8540, "HTTP port of node 0; node i uses port + i")
	period := fs.Uint64("block-period", 1, "block period in seconds")
	epochLen := fs.Uint64("epoch-length", 100, "blocks per epoch")
	_ = fs.Parse(args)
	if *nodes < 1 {
		return errors.New("-nodes must be at least 1")
	}
	vals := make([]kvstore.Validator, *nodes)
	for i := range vals {
		home := filepath.Join(*dir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(home, 0o700); err != nil {
			return err
		}
		v, err := kvstore.NewKeyFile(filepath.Join(home, "nodekey"))
		if err != nil {
			return err
		}
		vals[i] = v
	}
	g, err := kvstore.NewGenesis(kvstore.GenesisParams{ChainID: 1337, BlockPeriodSeconds: *period, RequestTimeoutSeconds: 2,
		EpochLength: *epochLen, Time: uint64(time.Now().Unix())}, vals)
	if err != nil {
		return err
	}
	for i, v := range vals {
		home := filepath.Join(*dir, fmt.Sprintf("node%d", i))
		if err := g.Write(filepath.Join(home, "genesis.json")); err != nil {
			return err
		}
		nf := nodeFile{Self: v.Address, Listen: fmt.Sprintf("127.0.0.1:%d", *p2pBase+i), HTTP: fmt.Sprintf("127.0.0.1:%d", *httpBase+i),
			Network: "kvstore-devnet"}
		for j, pv := range vals {
			if j != i {
				nf.Peers = append(nf.Peers, peerFile{Addr: pv.Address, Endpoint: fmt.Sprintf("127.0.0.1:%d", *p2pBase+j)})
			}
		}
		raw, err := json.MarshalIndent(nf, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(home, "node.json"), append(raw, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("node%d %s http://%s\n", i, v.Address.Hex(), nf.HTTP)
	}
	return nil
}

func startCmd(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	home := fs.String("home", "./devnet/node0", "node directory written by init")
	verbose := fs.Bool("v", false, "debug logs")
	_ = fs.Parse(args)
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	raw, err := os.ReadFile(filepath.Join(*home, "node.json"))
	if err != nil {
		return err
	}
	var nf nodeFile
	if err := json.Unmarshal(raw, &nf); err != nil {
		return err
	}
	g, err := kvstore.ReadGenesis(filepath.Join(*home, "genesis.json"))
	if err != nil {
		return err
	}
	peers := make([]devnet.Peer, len(nf.Peers))
	for i, p := range nf.Peers {
		peers[i] = devnet.Peer{Addr: p.Addr, Endpoint: p.Endpoint}
	}
	nd, err := kvstore.NewNode(kvstore.NodeConfig{Home: *home, Genesis: g, KeyFile: filepath.Join(*home, "nodekey"), Self: nf.Self,
		Listen: nf.Listen, Network: nf.Network, Peers: peers, Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := nd.Start(ctx); err != nil {
		return err
	}
	srv := &http.Server{Addr: nf.HTTP, Handler: api(nd), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
		}
	}()
	log.Info("node started", "address", nf.Self.Hex(), "p2p", nf.Listen, "http", nf.HTTP, "head", nd.App.Head().Number)
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return nd.Stop()
}

// api is the HTTP API of a node.
func api(nd *kvstore.Node) http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("POST /tx", func(w http.ResponseWriter, r *http.Request) {
		var t kvstore.Tx
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, kvstore.MaxValue+4096)).Decode(&struct {
			From  *types.Address `json:"from"`
			Nonce *uint64        `json:"nonce"`
			Key   *string        `json:"key"`
			Value *string        `json:"value"`
		}{&t.From, &t.Nonce, &t.Key, &t.Value}); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		raw, err := t.Encode()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		resp, err := nd.Node.Mempool().Add(r.Context(), raw)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		if resp.Code != mempool.CodeOK {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": resp.Reason})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"hash": kvstore.TxKey(raw).Hex()})
	})
	mux.HandleFunc("GET /kv/{key}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := nd.App.Get(r.PathValue("key"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"key": r.PathValue("key"), "value": v})
	})
	mux.HandleFunc("GET /nonce/{addr}", func(w http.ResponseWriter, r *http.Request) {
		var a types.Address
		if err := a.UnmarshalText([]byte(r.PathValue("addr"))); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]uint64{"nonce": nd.App.Nonce(a)})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		h := nd.App.Head()
		writeJSON(w, http.StatusOK, map[string]string{"height": h.Number.String(), "hash": codec.BlockHash(h).Hex()})
	})
	mux.Handle("POST /rpc", rpc.Handler(nd.Node.APIs()))
	return mux
}
