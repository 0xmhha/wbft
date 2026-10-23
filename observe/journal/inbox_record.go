package journal

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

const InboxSourceVersion uint64 = 1

// InboxRec records mutex-ordered queue/slot operations and the immutable
// snapshot publication used by a receive check. Request is the original append
// sequence. This evidence does not close the runner schedule or prove socket I/O.
// The v1 wire value is RLP([format, journal-sequence, source]).
type InboxRec struct {
	Version, Sequence, Request, OldRequest uint64
	Action, Result                         string
	EngineRun, Step                        uint64
	SnapshotEngine, SnapshotStep           uint64
	SnapshotPhase                          string
	SnapshotReplayed                       uint64
	SnapshotContextHash                    types.Hash
	Peer, Holder, Signer                   types.Address
	ViewSequence, ViewRound                string
	Second                                 uint64
	Code                                   uint64
	Payload                                []byte
	Capture, RecvMono                      uint64
	Origin                                 transport.ReceiveOrigin
	StreamRun                              string
	Stream                                 uint64
	Before, After, BytesBefore, BytesAfter uint64
	Order, Candidates                      []types.Address
	WorkerCursor, ConsensusCursor          uint64
	Choice, Manual                         uint64
	Mono, WallNs                           uint64
	Unavailable                            string
}

type inboxRLP struct {
	Format, JSeq uint64
	Source       InboxRec
}

// InboxSnapshotDigest covers exactly the published context used by membership
// and view-window checks, including ordered authority/key-presence metadata.
func InboxSnapshotDigest(snapshot *consensus.Snapshot) (types.Hash, error) {
	context, known, err := coreSourceContext(snapshot)
	if err != nil {
		return types.Hash{}, err
	}
	encoded, err := rlp.Encode(&struct {
		Domain  string
		Known   uint64
		Context validationContextRLP
	}{"wbft/inbox-snapshot/v1", boolUint(known), receiveContextWire(context)})
	if err != nil {
		return types.Hash{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validInboxRec(r *InboxRec) bool {
	if r.Version != InboxSourceVersion || r.Mono > math.MaxInt64 || r.Second > 1 || r.Manual > 1 || r.RecvMono > math.MaxInt64 || r.SnapshotReplayed > 1 {
		return false
	}
	switch r.Unavailable {
	case "", "metadata_exhausted", "snapshot_unavailable", "snapshot_encoding", "dispatch_source_missing", "dispatch_deduplicated":
	default:
		return false
	}
	if (r.Sequence == 0) != (r.Unavailable == "metadata_exhausted") {
		return false
	}
	if r.Action != "append" && len(r.Payload) > 0 {
		return false
	}
	if r.Action != "check" && (r.Result != "" || r.SnapshotEngine != 0 || r.SnapshotStep != 0 || r.SnapshotPhase != "" || r.SnapshotReplayed != 0 || r.SnapshotContextHash != (types.Hash{})) {
		return false
	}
	if r.Action != "take" && r.Action != "dispatch" && r.Action != "discard" && r.Action != "clear" && (r.EngineRun != 0 || r.Step != 0) {
		return false
	}
	if r.Action != "dequeue" && (len(r.Candidates) != 0 || r.Choice != 0 || r.Manual != 0) {
		return false
	}
	if r.Action == "dequeue" && r.Manual == 0 && r.Choice != 0 {
		return false
	}
	if r.Action != "append" && r.Action != "dequeue" && r.Action != "clear" && (r.Before != 0 || r.After != 0 || r.BytesBefore != 0 || r.BytesAfter != 0) {
		return false
	}
	slotResult := r.Action == "check" && (r.Result == "insert" || r.Result == "replace" || r.Result == "duplicate")
	if r.Action == "take" || slotResult {
		if !canonicalContextNumber(r.ViewSequence) || !canonicalContextNumber(r.ViewRound) || r.Second == 1 && (r.Code != uint64(codec.CodePreprepare) || r.ViewRound != "0") {
			return false
		}
	} else if r.Holder != (types.Address{}) || r.Signer != (types.Address{}) || r.ViewSequence != "" || r.ViewRound != "" || r.Second != 0 || r.OldRequest != 0 {
		return false
	}
	if r.Action != "check" && r.OldRequest != 0 {
		return false
	}
	if r.Action == "check" && r.Unavailable == "" {
		switch r.SnapshotPhase {
		case "initial":
			if r.SnapshotEngine != 0 || r.SnapshotStep != 0 || r.SnapshotReplayed != 0 {
				return false
			}
		case "start", "step", "replay", "stopped":
			if r.SnapshotEngine == 0 || r.SnapshotStep == 0 {
				return false
			}
		default:
			return false
		}
	}
	switch r.Action {
	case "append":
		return r.Request == r.Sequence && r.Before < math.MaxUint64 && r.After == r.Before+1 && uint64(len(r.Payload)) <= math.MaxUint64-r.BytesBefore && r.BytesAfter == r.BytesBefore+uint64(len(r.Payload))
	case "dequeue":
		return (r.Request > 0 || r.Unavailable != "") && r.Before > 0 && r.After == r.Before-1 && r.BytesBefore >= r.BytesAfter && len(r.Candidates) > 0
	case "check":
		if r.Request == 0 && r.Unavailable == "" {
			return false
		}
		switch r.Result {
		case "insert", "replace", "duplicate", "signature", "membership", "window":
			return true
		}
	case "take", "discard":
		return (r.Request > 0 || r.Unavailable != "") && r.EngineRun > 0 && r.Step == 0
	case "dispatch":
		return (r.Request > 0 || r.Unavailable != "") && r.EngineRun > 0 && r.Step > 0
	case "clear":
		return r.Request == 0 && r.EngineRun > 0 && r.Step > 0 && r.After == 0 && r.BytesAfter == 0 && r.Peer == (types.Address{}) && r.Code == 0 && r.Capture == 0 && r.RecvMono == 0 && r.Origin == (transport.ReceiveOrigin{}) && r.StreamRun == "" && r.Stream == 0
	}
	return false
}

func encodeInboxRec(r *InboxRec, jseq uint64) ([]byte, error) {
	if !validInboxRec(r) {
		return nil, fmt.Errorf("journal: invalid inbox source")
	}
	return rlp.Encode(&inboxRLP{Format: Format, JSeq: jseq, Source: *r})
}

func decodeInboxRec(body []byte) (Record, error) {
	var wire inboxRLP
	if err := rlp.DecodeStrict(body, &wire); err != nil {
		return Record{}, fmt.Errorf("%w: inbox source: %v", ErrRecord, err)
	}
	if wire.Format != Format || !validInboxRec(&wire.Source) {
		return Record{}, fmt.Errorf("%w: invalid inbox source", ErrRecord)
	}
	return Record{Kind: KindInbox, JSeq: wire.JSeq, Body: &wire.Source}, nil
}
