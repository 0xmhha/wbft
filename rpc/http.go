package rpc

import (
	"encoding/json"
	"io"
	"net/http"
)

// maxRequest bounds the body of a request.
const maxRequest = 1 << 20

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
}

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
// the wbft namespace, which take no parameters.
func Handler(apis []API) http.Handler {
	methods := map[string]func() any{}
	for _, a := range apis {
		if s, ok := a.Service.(*Service); ok {
			methods[a.Namespace+"_nodeInfo"] = func() any { return s.NodeInfo() }
			methods[a.Namespace+"_consensusState"] = func() any { return s.ConsensusState() }
			methods[a.Namespace+"_peers"] = func() any { return s.Peers() }
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
			resp.ID, resp.Result = req.ID, methods[req.Method]()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
