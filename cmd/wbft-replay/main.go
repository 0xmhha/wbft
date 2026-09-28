// Command wbft-replay replays a recorded message journal through the
// consensus core and reports, step by step, whether the replayed outputs
// match the recorded ones. It wraps conformance/stepdriver.RunTrace.
//
// With -journal it replays one journal directory and prints a summary:
//
//	wbft-replay -journal DIR -chain FILE [-v]
//
// Without flags it speaks the line-based JSON protocol wbft-replay/1 on
// standard input and output, one object per line:
//
//	-> {"type":"hello","protocol":"wbft-replay/1"}
//	<- {"type":"hello","protocol":"wbft-replay/1","impl":"wbft"}
//	-> {"type":"replay","id":1,"journal":DIR,"chain":FILE,"from_step":0,"to_step":0,"with_vars":false}
//	<- {"type":"step","id":1,"engine_run":1,"step":1,"input":"start","out_digest":"0x..","match":true,"outputs":3}
//	<- {"type":"done","id":1,"steps":N,"mismatches":M}
//	-> {"type":"bye"}
//
// chain is a file of RLP-encoded canonical blocks from genesis (the
// chain.rlp of a simulator export). A failed request is answered with
// {"type":"error","id":ID,"error":TEXT}.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
)

// Protocol is the protocol name of the standard input mode.
const Protocol = "wbft-replay/1"

func main() {
	jdir := flag.String("journal", "", "journal directory to replay")
	chain := flag.String("chain", "", "chain file (RLP list of blocks from genesis)")
	verbose := flag.Bool("v", false, "print every step")
	flag.Parse()
	if *jdir != "" {
		os.Exit(replayOnce(*jdir, *chain, *verbose, os.Stdout))
	}
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wbft-replay:", err)
		os.Exit(1)
	}
}

func replayOnce(dir, chain string, verbose bool, w io.Writer) int {
	var steps, bad int
	err := replay(dir, chain, stepdriver.TraceOptions{}, func(s stepdriver.StepResult) error {
		steps++
		if !s.Match {
			bad++
		}
		if verbose || !s.Match {
			fmt.Fprintf(w, "run %d step %d %s match=%t outputs=%d\n", s.EngineRun, s.Step, inputlog.Kind(s.Input), s.Match, len(s.Outputs))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wbft-replay:", err)
		return 2
	}
	fmt.Fprintf(w, "steps %d mismatches %d\n", steps, bad)
	if bad > 0 {
		return 1
	}
	return 0
}

func replay(dir, chain string, opts stepdriver.TraceOptions, yield func(stepdriver.StepResult) error) error {
	b, err := os.ReadFile(chain)
	if err != nil {
		return err
	}
	blocks, err := sim.DecodeChain(b)
	if err != nil {
		return fmt.Errorf("chain file: %w", err)
	}
	src, err := sim.NewChainSource(blocks)
	if err != nil {
		return err
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("journal directory %s: not a directory", dir)
	}
	r, err := journal.OpenReader(fsys.OS{}, dir)
	if err != nil {
		return err
	}
	opts.Blocks = src
	return stepdriver.RunTrace(r, opts, yield)
}

type request struct {
	Type     string `json:"type"`
	ID       uint64 `json:"id"`
	Protocol string `json:"protocol"`
	Journal  string `json:"journal"`
	Chain    string `json:"chain"`
	FromStep uint64 `json:"from_step"`
	ToStep   uint64 `json:"to_step"`
	WithVars bool   `json:"with_vars"`
}

// serve answers protocol requests until "bye" or the end of the input.
func serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	enc := json.NewEncoder(out)
	send := func(v any) error { return enc.Encode(v) }
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			if err := send(map[string]any{"type": "error", "error": "malformed request: " + err.Error()}); err != nil {
				return err
			}
			continue
		}
		switch req.Type {
		case "hello":
			if err := send(map[string]any{"type": "hello", "protocol": Protocol, "impl": "wbft"}); err != nil {
				return err
			}
		case "replay":
			steps, bad := 0, 0
			opts := stepdriver.TraceOptions{FromStep: req.FromStep, ToStep: req.ToStep, WithVars: req.WithVars}
			err := replay(req.Journal, req.Chain, opts, func(s stepdriver.StepResult) error {
				steps++
				if !s.Match {
					bad++
				}
				m := map[string]any{"type": "step", "id": req.ID, "engine_run": s.EngineRun, "step": s.Step,
					"input": inputlog.Kind(s.Input), "out_digest": "0x" + hex.EncodeToString(s.OutDigest[:]),
					"match": s.Match, "outputs": len(s.Outputs)}
				if s.Vars != nil {
					m["vars"] = json.RawMessage(stepdriver.VarsJSON(s.Vars))
				}
				return send(m)
			})
			if err != nil {
				if err := send(map[string]any{"type": "error", "id": req.ID, "error": err.Error()}); err != nil {
					return err
				}
				continue
			}
			if err := send(map[string]any{"type": "done", "id": req.ID, "steps": steps, "mismatches": bad}); err != nil {
				return err
			}
		case "bye":
			return nil
		default:
			if err := send(map[string]any{"type": "error", "id": req.ID, "error": "unknown request type " + req.Type}); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
