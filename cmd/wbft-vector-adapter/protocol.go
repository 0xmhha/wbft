package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime/debug"
)

// protocolName is the adapter protocol this program speaks.
const protocolName = "wbft-vector/1"

// Exit statuses.
const (
	exitOK       = 0 // session ended with bye (WBFT-VEC-046)
	exitEOF      = 1 // standard input closed before bye
	exitProtocol = 2 // the runner broke the protocol, or a usage error
	exitUsage    = exitProtocol
)

// Impl is the "impl" object of the adapter's hello (WBFT-VEC-038).
type Impl struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Lang    string `json:"lang"`
	Build   string `json:"build"`
}

// helloReply is the adapter's hello (WBFT-VEC-038).
type helloReply struct {
	Type     string   `json:"type"`
	Protocol string   `json:"protocol"`
	Impl     Impl     `json:"impl"`
	Handlers []string `json:"handlers"`
	// Improvements lists optional behaviour switches that are enabled.
	// A conformance run reports an empty list.
	Improvements []string `json:"improvements"`
}

// incoming is the union of the runner's messages (WBFT-VEC-037, -040, -045).
type incoming struct {
	Type     string          `json:"type"`
	Protocol string          `json:"protocol"`
	ID       json.RawMessage `json:"id"`
	// Runner is an object in hello and a string in case messages.
	Runner  json.RawMessage `json:"runner"`
	Handler *string         `json:"handler"`
	Case    string          `json:"case"`
	Kind    string          `json:"kind"`
	Input   json.RawMessage `json:"input"`

	runnerName string // Runner of a case message, decoded by parse
}

// result is the adapter's answer to one case (WBFT-VEC-043).
type result struct {
	Type       string          `json:"type"`
	ID         json.RawMessage `json:"id"`
	Status     string          `json:"status"`
	Output     json.RawMessage `json:"output,omitempty"`
	ErrorClass string          `json:"error_class,omitempty"`
	Message    string          `json:"message,omitempty"`
}

// jsonInteger matches a JSON number without fraction or exponent.
var jsonInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// errProtocol reports a message the adapter cannot answer.
var errProtocol = errors.New("protocol error")

// serve runs one session from the runner's hello to bye and returns the exit
// status. Only protocol messages are written to out (WBFT-VEC-034).
func serve(in io.Reader, out, diag io.Writer, impl Impl) int {
	r := bufio.NewReaderSize(in, 1<<20) // lines may be long (WBFT-VEC-036)
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w) // Encode ends each message with one '\n' (WBFT-VEC-033)
	enc.SetEscapeHTML(false)
	send := func(v any) error {
		if err := enc.Encode(v); err != nil {
			return err
		}
		return w.Flush()
	}

	helloDone := false
	for {
		line, err := readLine(r)
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(diag, "wbft-vector-adapter: standard input closed before bye")
			return exitEOF
		}
		if err != nil {
			fmt.Fprintf(diag, "wbft-vector-adapter: read: %v\n", err)
			return exitProtocol
		}
		msg, err := parse(line)
		if err != nil {
			fmt.Fprintf(diag, "wbft-vector-adapter: %v\n", err)
			return exitProtocol
		}
		switch {
		case msg.Type == "hello" && !helloDone:
			if msg.Protocol != protocolName {
				// The runner ends the session when the names differ
				// (WBFT-VEC-039); answer with our own name so it can tell.
				fmt.Fprintf(diag, "wbft-vector-adapter: runner speaks %q, adapter speaks %q\n", msg.Protocol, protocolName)
			}
			helloDone = true
			err = send(helloReply{
				Type:         "hello",
				Protocol:     protocolName,
				Impl:         impl,
				Handlers:     handlerNames(),
				Improvements: []string{},
			})
		case msg.Type == "case" && helloDone:
			var res result
			res, err = answer(msg, diag)
			if err == nil {
				err = send(res)
			}
		case msg.Type == "bye" && helloDone:
			return exitOK
		default:
			fmt.Fprintf(diag, "wbft-vector-adapter: %v: unexpected message type %q (hello received: %t)\n", errProtocol, msg.Type, helloDone)
			return exitProtocol
		}
		if err != nil {
			fmt.Fprintf(diag, "wbft-vector-adapter: %v\n", err)
			return exitProtocol
		}
	}
}

// readLine returns the next line without its terminating line feed. A final
// line without a line feed is returned as is; io.EOF means no more input.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if errors.Is(err, io.EOF) && len(line) > 0 {
		return line, nil
	}
	if err != nil {
		return nil, err
	}
	return line[:len(line)-1], nil
}

// parse decodes one line into a runner message and checks the envelope.
func parse(line []byte) (incoming, error) {
	var msg incoming
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return msg, fmt.Errorf("%w: line is not a JSON object", errProtocol)
	}
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		return msg, fmt.Errorf("%w: %v", errProtocol, err)
	}
	if msg.Type == "case" {
		// id must be a JSON integer (WBFT-VEC-040); it is echoed verbatim so
		// that large values keep their exact digits.
		if !jsonInteger.Match(msg.ID) {
			return msg, fmt.Errorf("%w: case id %q is not a JSON integer", errProtocol, msg.ID)
		}
		if json.Unmarshal(msg.Runner, &msg.runnerName) != nil || msg.Handler == nil {
			return msg, fmt.Errorf("%w: case %s lacks a runner or handler string", errProtocol, msg.ID)
		}
	}
	return msg, nil
}

// answer computes the result of one case. Each case is computed on its own,
// without state from earlier cases (WBFT-VEC-053).
func answer(msg incoming, diag io.Writer) (res result, err error) {
	res = result{Type: "result", ID: msg.ID}
	name := msg.runnerName + "/" + *msg.Handler
	defer func() {
		// A panicking handler fails its case, not the session.
		if p := recover(); p != nil {
			fmt.Fprintf(diag, "wbft-vector-adapter: case %s (%s %s) panicked: %v\n%s", msg.ID, name, msg.Case, p, debug.Stack())
			res = result{Type: "result", ID: msg.ID, Status: "error", ErrorClass: "internal", Message: "handler panicked"}
			err = nil
		}
	}()
	out, herr := dispatch(name, msg.Kind, msg.Input)
	switch {
	case errors.Is(herr, errUnsupported):
		res.Status = "unsupported"
	case herr != nil:
		res.Status = "error"
		res.Message = herr.Error() // informative (WBFT-VEC-043)
	default:
		raw, merr := json.Marshal(out)
		if merr != nil {
			return res, fmt.Errorf("case %s: encode output: %w", msg.ID, merr)
		}
		if len(raw) == 0 || raw[0] != '{' {
			return res, fmt.Errorf("case %s: output of %s is not a JSON object", msg.ID, name)
		}
		res.Status = "ok"
		res.Output = raw
	}
	return res, nil
}
