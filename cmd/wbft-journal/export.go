package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// The R-01 frame dump (inspector requirements-on-nodes.md 2): one JSON Lines
// file per writer run and the payloads in a content-addressed directory.
//
//	<out>/frames-<run>.jsonl
//	<out>/payloads/<ab>/<sha256>
//
// The journal does not hold the engine state at receipt, the hits of the
// two dedup caches or (yet) the send cause, so frame records carry none of
// these. A conn record carries the times of the record before it, since peer
// records have no times of their own. An outcome the core journaled before
// the adapter journaled its frame follows the frame in the file and keeps
// its own (lower) seq; one whose frame does not come within
// outcomeLinkWindow records has "of": null.

// r01Version is the format version of the records (field v).
const r01Version = 1

// outcomeLinkWindow is how many later records an outcome may wait for the
// received frame it belongs to: the adapter journals a frame after it
// offered it, so the core's outcome can come first.
const outcomeLinkWindow = 4096

type exportRun struct {
	Run     string `json:"run"`
	File    string `json:"file"`
	Records int64  `json:"records"`
}

type exportResult struct {
	Out      string       `json:"out"`
	Format   string       `json:"format"`
	From     string       `json:"from,omitempty"`
	To       string       `json:"to,omitempty"`
	Runs     []*exportRun `json:"runs"`
	Payloads int64        `json:"payloads"` // payload files written
	// Unlinked counts outcome records whose received frame was not found
	// (of is null); outcomes of the node's own messages (via self) have no
	// frame and are not counted.
	Unlinked int64 `json:"unlinked"`
}

// linkKey identifies the received copies of one message from one peer.
type linkKey struct {
	peer types.Address
	key  types.Hash
}

// pendingOutcome is an outcome journaled before its frame.
type pendingOutcome struct {
	key  linkKey
	rec  map[string]any
	left int // records it may still wait
}

// r01Writer turns the records of one journal into R-01 files.
type r01Writer struct {
	fs  fsys.FS
	out string
	res *exportResult

	from, to *types.Height

	file  fsys.File
	run   *exportRun
	node  types.Address
	head  *types.Height // the head of the last step
	wall  int64
	mono  time.Duration
	peers map[uint32]*journal.PeerRec
	on    map[uint32]bool // attached peers (segment headers repeat them)
	last  map[linkKey]uint64
	wait  []*pendingOutcome // in journal order
	saved map[string]bool
}

func exportR01(fs fsys.FS, dir, out, fromArg, toArg string) (*exportResult, error) {
	w := &r01Writer{fs: fs, out: out, res: &exportResult{Out: out, Format: "r01", Runs: []*exportRun{}, From: fromArg, To: toArg},
		saved: map[string]bool{}}
	var err error
	if w.from, err = parseHeight("--from", fromArg); err != nil {
		return nil, err
	}
	if w.to, err = parseHeight("--to", toArg); err != nil {
		return nil, err
	}
	if err := fs.MkdirAll(filepath.Join(out, "payloads"), 0o700); err != nil {
		return nil, err
	}
	var werr error
	end := scan(fs, dir, func(rec journal.Record, _ wal.Position) {
		if werr == nil {
			werr = w.record(rec)
		}
	})
	if werr == nil {
		werr = w.closeRun()
	}
	if werr != nil {
		return nil, werr
	}
	if end != nil {
		return w.res, fmt.Errorf("the journal reads only up to a damaged record: %w", end)
	}
	return w.res, nil
}

func parseHeight(flagName, s string) (*types.Height, error) {
	if s == "" {
		return nil, nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("%s %q is not a decimal height", flagName, s)
	}
	h, err := types.HeightFromBig(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	return &h, nil
}

// inRange reports whether the height being decided (head + 1) is in the
// requested range; before the first step of a run it is unknown and only
// an export without --from includes the record.
func (w *r01Writer) inRange() bool {
	if w.head == nil {
		return w.from == nil
	}
	h := w.head.AddUint64(1)
	return (w.from == nil || h.Cmp(*w.from) >= 0) && (w.to == nil || h.Cmp(*w.to) <= 0)
}

func (w *r01Writer) record(rec journal.Record) error {
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if w.run == nil || w.run.Run != b.Run {
			if err := w.openRun(b); err != nil {
				return err
			}
		}
	case *journal.StepRec:
		h := b.HeadNumber
		w.head, w.wall, w.mono = &h, b.WallNs, b.Mono
	case *journal.PeerRec:
		return w.peer(rec.JSeq, b)
	case *journal.MsgRec:
		w.wall, w.mono = b.WallNs, b.Mono
		return w.msg(rec.JSeq, b)
	case *journal.OutcomeRec:
		return w.outcome(rec.JSeq, b)
	case *journal.SuppressedRec:
		if !w.inRange() {
			return nil
		}
		r := w.common("send_suppressed", rec.JSeq)
		r["peer"] = w.peerAddr(b.PeerIdx)
		r["dedup_key"] = hexHash(b.DedupKey)
		r["reason"] = b.Reason
		if b.Cause != "" {
			r["cause"] = b.Cause
		}
		return w.write(r)
	case *journal.GapRec:
		r := w.common("dropped", rec.JSeq)
		r["count"] = b.Dropped
		return w.write(r)
	}
	return w.tick()
}

func (w *r01Writer) openRun(s *journal.SegmentRec) error {
	if err := w.closeRun(); err != nil {
		return err
	}
	name := "frames-" + safeName(s.Run) + ".jsonl"
	f, err := w.fs.OpenFile(filepath.Join(w.out, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	w.file, w.node, w.head = f, s.Self, nil
	w.peers, w.on = map[uint32]*journal.PeerRec{}, map[uint32]bool{}
	w.last, w.wait = map[linkKey]uint64{}, nil
	w.run = &exportRun{Run: s.Run, File: name}
	w.res.Runs = append(w.res.Runs, w.run)
	return nil
}

// closeRun writes the outcomes still waiting for their frame and closes the
// file of the run.
func (w *r01Writer) closeRun() error {
	if w.file == nil {
		return nil
	}
	for _, p := range w.wait {
		if err := w.write(p.rec); err != nil {
			return err
		}
		w.res.Unlinked++
	}
	w.wait = nil
	err := w.file.Close()
	w.file = nil
	return err
}

// tick ages the outcomes waiting for their frame and writes, unlinked,
// those that waited too long.
func (w *r01Writer) tick() error {
	kept := w.wait[:0]
	for _, p := range w.wait {
		if p.left--; p.left > 0 {
			kept = append(kept, p)
			continue
		}
		if err := w.write(p.rec); err != nil {
			return err
		}
		w.res.Unlinked++
	}
	w.wait = kept
	return nil
}

func safeName(s string) string {
	b := []byte(s)
	for i, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }
func hexHash(h types.Hash) string    { return "0x" + hex.EncodeToString(h[:]) }

func (w *r01Writer) common(typ string, seq uint64) map[string]any {
	return map[string]any{"v": r01Version, "type": typ, "node": hexAddr(w.node), "run": w.run.Run, "seq": seq,
		"t_wall": time.Unix(0, w.wall).UTC().Format("2006-01-02T15:04:05.000000000Z"), "t_mono_ns": int64(w.mono)}
}

func (w *r01Writer) peerAddr(idx uint32) any {
	if p := w.peers[idx]; p != nil {
		return hexAddr(p.Addr)
	}
	return nil
}

func (w *r01Writer) peer(seq uint64, b *journal.PeerRec) error {
	if w.run == nil {
		return nil
	}
	c := *b
	w.peers[b.PeerIdx] = &c
	r := w.common("conn", seq)
	r["peer"] = hexAddr(b.Addr)
	if len(b.NodeID) > 0 {
		r["peer_id"] = hex.EncodeToString(b.NodeID)
	}
	switch b.Event {
	case "attached":
		if w.on[b.PeerIdx] { // repeated at the start of a segment
			return nil
		}
		w.on[b.PeerIdx] = true
		r["event"] = "istanbul_attached"
		if b.Remote != "" {
			r["remote"] = b.Remote
		}
	default:
		delete(w.on, b.PeerIdx)
		r["event"] = "closed"
		r["reason"] = b.Reason
	}
	if !w.inRange() {
		return nil
	}
	return w.write(r)
}

// inOutcome is the R-01 outcome of a received frame from the journal's
// offer: delivered frames wait for the core (PENDING); the others were
// decided on the receive path.
func inOutcome(offer string) string {
	switch offer {
	case transport.OfferQueued:
		return "PENDING"
	case transport.OfferFrameDisconnect:
		return "DISCONNECT"
	default: // frame_ignore, queue_full
		return "DROP_SILENT"
	}
}

func (w *r01Writer) msg(seq uint64, b *journal.MsgRec) error {
	if w.run == nil || !w.inRange() {
		return w.tick()
	}
	r := w.common("frame", seq)
	r["dir"] = b.Dir
	r["peer"] = w.peerAddr(b.PeerIdx)
	if p := w.peers[b.PeerIdx]; p != nil && len(p.NodeID) > 0 {
		r["peer_id"] = hex.EncodeToString(p.NodeID)
	}
	r["code"] = fmt.Sprintf("%#x", b.Code)
	r["wire_code"] = b.WireCode
	r["size"] = len(b.Payload)
	if b.Payload != nil {
		sum, err := w.payload(b.Payload)
		if err != nil {
			return err
		}
		r["payload_sha256"] = sum
	}
	r["dedup_key"] = hexHash(b.DedupKey)
	if b.Dir == journal.In {
		r["outcome"] = inOutcome(b.Offer)
	} else {
		if b.Write != "" && b.Write != transport.WriteOK {
			r["write_error"] = b.Write
		}
		if b.Cause != "" {
			r["cause"] = b.Cause
		}
		if b.RelayOf != 0 {
			r["relay_of"] = b.RelayOf
		}
	}
	if err := w.write(r); err != nil {
		return err
	}
	if p := w.peers[b.PeerIdx]; b.Dir == journal.In && p != nil {
		k := linkKey{peer: p.Addr, key: b.DedupKey}
		w.last[k] = seq
		// Outcomes journaled before this frame belong to it; they follow it
		// in the file and keep their own seq.
		kept := w.wait[:0]
		for _, o := range w.wait {
			if o.key != k {
				kept = append(kept, o)
				continue
			}
			o.rec["of"] = seq
			if err := w.write(o.rec); err != nil {
				return err
			}
		}
		w.wait = kept
	}
	return w.tick()
}

func (w *r01Writer) outcome(seq uint64, b *journal.OutcomeRec) error {
	if w.run == nil || !w.inRange() {
		return w.tick()
	}
	r := w.common("outcome", seq)
	r["outcome"] = string(b.Outcome)
	r["check"] = b.Check
	if b.ErrorClass != "" {
		r["error_class"] = b.ErrorClass
	} else {
		r["error_class"] = nil
	}
	r["via"] = b.Via
	if b.Row >= 0 {
		r["row"] = b.Row
	}
	if b.Reason != "" {
		r["reason"] = b.Reason
	}
	k := linkKey{peer: b.Peer, key: b.DedupKey}
	switch {
	case b.Of != 0:
		r["of"] = b.Of
	case b.Via == "self": // the node's own message: no frame was received
		r["of"] = nil
	case w.last[k] != 0:
		r["of"] = w.last[k]
	default:
		r["of"] = nil
		w.wait = append(w.wait, &pendingOutcome{key: k, rec: r, left: outcomeLinkWindow})
		return w.tick()
	}
	if err := w.write(r); err != nil {
		return err
	}
	return w.tick()
}

// payload stores a payload under its sha256 once and returns the hex sum.
func (w *r01Writer) payload(p []byte) (string, error) {
	s := sha256.Sum256(p)
	sum := hex.EncodeToString(s[:])
	if w.saved[sum] {
		return sum, nil
	}
	dir := filepath.Join(w.out, "payloads", sum[:2])
	if err := w.fs.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := w.fs.OpenFile(filepath.Join(dir, sum), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(p); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	w.saved[sum] = true
	w.res.Payloads++
	return sum, nil
}

func (w *r01Writer) write(r map[string]any) error {
	if w.file == nil {
		return errors.New("a record before the first segment record")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := w.file.Write(b); err != nil {
		return err
	}
	w.run.Records++
	return nil
}
