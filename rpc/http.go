package rpc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// maxRequest bounds the body of a request.
const maxRequest = 1 << 20

type request struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

// method answers a request from its parameters.
type method func(params []json.RawMessage) (any, error)

// errParams reports parameters a method cannot take.
var errParams = errors.New("invalid params")

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Handler serves the services of apis as JSON-RPC 2.0 over HTTP POST, for
// applications without an RPC server of their own. It serves the methods of
// the wbft namespace.
func Handler(apis []API) http.Handler {
	methods := map[string]method{}
	none := func(f func() any) method {
		return func(params []json.RawMessage) (any, error) {
			if len(params) != 0 {
				return nil, errParams
			}
			return f(), nil
		}
	}
	for _, a := range apis {
		if s, ok := a.Service.(*Service); ok {
			methods[a.Namespace+"_nodeInfo"] = none(func() any { return s.NodeInfo() })
			methods[a.Namespace+"_consensusState"] = none(func() any { return s.ConsensusState() })
			methods[a.Namespace+"_peers"] = none(func() any { return s.Peers() })
			ranged := func(f func(from, to HeightArg) (any, error)) method {
				return func(params []json.RawMessage) (any, error) {
					var from, to HeightArg
					if len(params) != 2 || json.Unmarshal(params[0], &from) != nil || json.Unmarshal(params[1], &to) != nil {
						return nil, errParams
					}
					return f(from, to)
				}
			}
			methods[a.Namespace+"_evidence"] = ranged(func(from, to HeightArg) (any, error) { return s.Evidence(from, to) })
			methods[a.Namespace+"_rejections"] = ranged(func(from, to HeightArg) (any, error) { return s.Rejections(from, to) })
			methods[a.Namespace+"_configAt"] = func(params []json.RawMessage) (any, error) {
				var h HeightArg
				if len(params) != 1 || json.Unmarshal(params[0], &h) != nil {
					return nil, errParams
				}
				return s.ConfigAt(h)
			}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest))
		var req request
		resp := response{JSONRPC: "2.0"}
		switch {
		case err != nil || json.Unmarshal(body, &req) != nil:
			resp.ID, resp.Error = json.RawMessage("null"), &rpcError{Code: -32700, Message: "parse error"}
		case methods[req.Method] == nil:
			resp.ID, resp.Error = req.ID, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
		default:
			resp.ID = req.ID
			res, err := methods[req.Method](req.Params)
			switch {
			case errors.Is(err, errParams):
				resp.Error = &rpcError{Code: -32602, Message: err.Error()}
			case err != nil:
				resp.Error = &rpcError{Code: -32000, Message: err.Error()}
			default:
				resp.Result = res
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
