package rpc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/0xmhha/wbft/types"
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
		if s, ok := a.Service.(*IstanbulService); ok {
			istanbulMethods(a.Namespace, s, methods)
		}
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
			methods[a.Namespace+"_events"] = func(params []json.RawMessage) (any, error) {
				var from uint64
				limit := 0
				if len(params) < 1 || len(params) > 2 || json.Unmarshal(params[0], &from) != nil ||
					len(params) == 2 && json.Unmarshal(params[1], &limit) != nil {
					return nil, errParams
				}
				return s.Events(from, limit)
			}
			methods[a.Namespace+"_headerCopy"] = func(params []json.RawMessage) (any, error) {
				var h types.Hash
				if len(params) != 1 || json.Unmarshal(params[0], &h) != nil {
					return nil, errParams
				}
				return s.HeaderCopy(h)
			}
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

// istanbulMethods serves the istanbul namespace over the handler: optional
// block numbers may be left out or null, as go-ethereum reads them.
func istanbulMethods(ns string, s *IstanbulService, methods map[string]method) {
	optional := func(params []json.RawMessage, i int) (*BlockNumber, error) {
		if i >= len(params) || string(params[i]) == "null" {
			return nil, nil
		}
		var n BlockNumber
		if err := json.Unmarshal(params[i], &n); err != nil {
			return nil, errParams
		}
		return &n, nil
	}
	hash := func(params []json.RawMessage) (types.Hash, error) {
		var h types.Hash
		if len(params) != 1 || json.Unmarshal(params[0], &h) != nil {
			return h, errParams
		}
		return h, nil
	}
	upTo := func(n int, f func(params []json.RawMessage) (any, error)) method {
		return func(params []json.RawMessage) (any, error) {
			if len(params) > n {
				return nil, errParams
			}
			return f(params)
		}
	}
	methods[ns+"_nodeAddress"] = upTo(0, func([]json.RawMessage) (any, error) { return s.NodeAddress(), nil })
	methods[ns+"_getCommitSignersFromBlock"] = upTo(1, func(p []json.RawMessage) (any, error) {
		n, err := optional(p, 0)
		if err != nil {
			return nil, err
		}
		return s.GetCommitSignersFromBlock(n)
	})
	methods[ns+"_getCommitSignersFromBlockByHash"] = func(p []json.RawMessage) (any, error) {
		h, err := hash(p)
		if err != nil {
			return nil, err
		}
		return s.GetCommitSignersFromBlockByHash(h)
	}
	methods[ns+"_getValidators"] = upTo(1, func(p []json.RawMessage) (any, error) {
		n, err := optional(p, 0)
		if err != nil {
			return nil, err
		}
		return s.GetValidators(n)
	})
	methods[ns+"_getValidatorsAtHash"] = func(p []json.RawMessage) (any, error) {
		h, err := hash(p)
		if err != nil {
			return nil, err
		}
		return s.GetValidatorsAtHash(h)
	}
	methods[ns+"_isValidator"] = upTo(1, func(p []json.RawMessage) (any, error) {
		n, err := optional(p, 0)
		if err != nil {
			return nil, err
		}
		return s.IsValidator(n)
	})
	methods[ns+"_status"] = upTo(2, func(p []json.RawMessage) (any, error) {
		start, err := optional(p, 0)
		if err != nil {
			return nil, err
		}
		end, err := optional(p, 1)
		if err != nil {
			return nil, err
		}
		return s.Status(start, end)
	})
	methods[ns+"_getWbftExtraInfo"] = func(p []json.RawMessage) (any, error) {
		var n BlockNumber
		if len(p) != 1 || json.Unmarshal(p[0], &n) != nil {
			return nil, errParams
		}
		return s.GetWbftExtraInfo(n)
	}
}
