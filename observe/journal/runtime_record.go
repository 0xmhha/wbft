package journal

import (
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/types"
)

const RuntimeSourceVersion uint64 = 1

type RuntimeComponent string

const (
	RuntimeReader      RuntimeComponent = "reader"
	RuntimeWriter      RuntimeComponent = "writer"
	RuntimeProtocol    RuntimeComponent = "protocol"
	RuntimeNodeStop    RuntimeComponent = "node_stop"
	RuntimeBaseStop    RuntimeComponent = "base_stop"
	RuntimeHostStop    RuntimeComponent = "host_stop"
	RuntimeDBClose     RuntimeComponent = "db_close"
	RuntimeAppStop     RuntimeComponent = "app_stop"
	RuntimeStackClose  RuntimeComponent = "stack_close"
	RuntimeWritersJoin RuntimeComponent = "writers_join"
)

// RuntimeRec is an original loop or shutdown call boundary. It records neither
// remote delivery nor physical persistence. A return requires its original entry.
// SessionRun/Session name the exact original stream; stop calls have no stream.
type RuntimeRec struct {
	Version, Sequence, Request uint64
	Namespace                  string
	Component                  RuntimeComponent
	Phase                      string
	SessionRun                 string
	Session                    uint64
	Peer                       types.Address
	Result                     string
	Mono, WallNs               uint64
	Unavailable                string
}

type runtimeRLP struct {
	Format, JSeq uint64
	Source       RuntimeRec
}

func runtimeLoop(component RuntimeComponent) bool {
	return component == RuntimeReader || component == RuntimeWriter || component == RuntimeProtocol
}

func validRuntimeRec(r *RuntimeRec) bool {
	if r.Version != RuntimeSourceVersion || r.Namespace == "" || r.Sequence == 0 || (r.Request == 0 && r.Unavailable != "loop_entry_missing") || r.Mono > math.MaxInt64 {
		return false
	}
	switch r.Component {
	case RuntimeReader, RuntimeWriter, RuntimeProtocol, RuntimeNodeStop, RuntimeBaseStop, RuntimeHostStop, RuntimeDBClose, RuntimeAppStop, RuntimeStackClose, RuntimeWritersJoin:
	default:
		return false
	}
	switch r.Unavailable {
	case "", "session_unqualified", "loop_entry_missing", "loop_entry_repeated":
	default:
		return false
	}
	if (r.SessionRun == "") != (r.Session == 0) {
		return false
	}
	if runtimeLoop(r.Component) {
		if r.Unavailable == "" && (r.SessionRun != r.Namespace || r.Session == 0) {
			return false
		}
	} else if r.Unavailable != "" || r.SessionRun != "" || r.Session != 0 || r.Peer != (types.Address{}) {
		return false
	}
	switch r.Phase {
	case "enter":
		return r.Request == r.Sequence && r.Result == ""
	case "return":
		if r.Request >= r.Sequence {
			return false
		}
		if runtimeLoop(r.Component) {
			return r.Result == "returned"
		}
		return r.Result == "ok" || r.Result == "error"
	default:
		return false
	}
}

func encodeRuntimeRec(r *RuntimeRec, jseq uint64) ([]byte, error) {
	if !validRuntimeRec(r) {
		return nil, fmt.Errorf("journal: invalid runtime source")
	}
	return rlp.Encode(&runtimeRLP{Format, jseq, *r})
}
func decodeRuntimeRec(raw []byte) (Record, error) {
	var w runtimeRLP
	if err := rlp.DecodeStrict(raw, &w); err != nil || w.Format != Format || !validRuntimeRec(&w.Source) {
		return Record{}, fmt.Errorf("%w: invalid runtime source", ErrRecord)
	}
	return Record{Kind: KindRuntime, JSeq: w.JSeq, Body: &w.Source}, nil
}
