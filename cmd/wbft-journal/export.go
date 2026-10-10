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
	"slices"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/event"
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
// A received frame carries the hits of the two dedup caches when the node
// checked it (a frame it did not queue, or received while the engine was
// not running, has no dedup), and the engine state the node had when it
// recorded the frame. A relay's relay_of is
// the last received frame with the same dedup key, since a relay sends the
// received bytes unchanged; a relay the node journaled before the frame it
// relays (the core can accept and relay a message before the receiver
// journals it) follows that frame in the file and keeps its own seq. A frame the node kept without its payload (too large) has its size,
// no payload_sha256 and a zero dedup_key. A conn record carries the times of
// the record before it, since peer
// records have no times of their own. An outcome is linked to a received
// frame the receiver took (offer queued) from the same peer with the same
// key: one decided while the frame was offered (AtOffer: a known key, the
// engine not running) to the next such frame, any other to the last one
// not settled that way, or to the next one when there is none yet. An
// outcome of a message the core processed later from its backlog (via
// backlog) has no peer: it is linked to the received frame of the same key
// that the core checked first (the frame it kept in the backlog). An
// outcome journaled before its frame follows the frame in the file and
// keeps its own (lower) seq; one whose frame does not come within
// outcomeLinkWindow records has "of": null, and a relay whose frame does not
// come within that window has no relay_of. A closed conn record carries who
// closed the stream (by: self, peer, unknown; unknown when the journal does
// not say) and, when the node did, the cause; a close for one received
// frame (cause frame or engine_stopped) has "of": the frame of that peer
// whose outcome was DISCONNECT. That frame or its outcome may be journaled
// after the close, which then waits for it like an outcome.

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
	// frame and are not counted. Relays whose received frame was not found
	// (no relay_of) are counted too.
	Unlinked int64 `json:"unlinked"`
}

// linkKey identifies the received copies of one message from one peer.
type linkKey struct {
	peer types.Address
	key  types.Hash
}

// pendingOutcome is an outcome journaled before its frame.
type pendingOutcome struct {
	key     linkKey
	rec     map[string]any
	left    int  // records it may still wait
	atOffer bool // decided while the frame was offered (journal AtOffer)
}

// pendingClose is a close for a received frame whose DISCONNECT was not
// journaled yet.
type pendingClose struct {
	peer types.Address
	rec  map[string]any
	left int // records it may still wait
}

// pendingRelay is a relay journaled before the frame it relays.
type pendingRelay struct {
	key  types.Hash
	rec  map[string]any
	left int // records it may still wait
}

// r01Writer turns the records of one journal into R-01 files.
type r01Writer struct {
	fs  fsys.FS
	out string
	res *exportResult

	from, to *types.Height

	file   fsys.File
	run    *exportRun
	node   types.Address
	head   *types.Height // the head of the last step
	wall   int64
	mono   time.Duration
	peers  map[uint32]*journal.PeerRec
	on     map[uint32]bool // attached peers (segment headers repeat them)
	last   map[linkKey]uint64
	lastIn map[types.Hash]uint64    // the last received frame of a message, from any peer
	wait   []*pendingOutcome        // in journal order
	relays []*pendingRelay          // in journal order
	closes []*pendingClose          // in journal order
	disc   map[types.Address]uint64 // the last frame of a peer that ended DISCONNECT, not yet named by a close
	core   map[types.Hash]uint64    // the received frame of a key the core checked first (a direct core outcome)
	saved  map[string]bool
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
	w.last, w.wait, w.relays, w.lastIn = map[linkKey]uint64{}, nil, nil, map[types.Hash]uint64{}
	w.closes, w.disc, w.core = nil, map[types.Address]uint64{}, map[types.Hash]uint64{}
	w.run = &exportRun{Run: s.Run, File: name}
	w.res.Runs = append(w.res.Runs, w.run)
	return nil
}

// closeRun writes the outcomes and relays still waiting for their frame and
// closes the file of the run.
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
	for _, p := range w.relays {
		if err := w.write(p.rec); err != nil {
			return err
		}
		w.res.Unlinked++
	}
	w.relays = nil
	for _, p := range w.closes {
		if err := w.write(p.rec); err != nil {
			return err
		}
	}
	w.closes = nil
	err := w.file.Close()
	w.file = nil
	return err
}

// tick ages the outcomes and relays waiting for their frame and writes,
// unlinked, those that waited too long.
func (w *r01Writer) tick() error {
	relays := w.relays[:0]
	for _, p := range w.relays {
		if p.left--; p.left > 0 {
			relays = append(relays, p)
			continue
		}
		if err := w.write(p.rec); err != nil {
			return err
		}
		w.res.Unlinked++
	}
	w.relays = relays
	closes := w.closes[:0]
	for _, p := range w.closes {
		if p.left--; p.left > 0 {
			closes = append(closes, p)
			continue
		}
		if err := w.write(p.rec); err != nil {
			return err
		}
	}
	w.closes = closes
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
		r["by"] = transport.ClosedByUnknown
		if b.By != "" {
			r["by"] = b.By
		}
		if b.By == transport.ClosedBySelf {
			r["cause"] = b.Cause
		}
	}
	if !w.inRange() {
		return nil
	}
	if r["event"] == "istanbul_attached" {
		delete(w.disc, b.Addr)
		return w.write(r)
	}
	if b.By == transport.ClosedBySelf && (b.Cause == transport.CloseFrame || b.Cause == transport.CloseEngineStopped) {
		if seq := w.disc[b.Addr]; seq != 0 {
			r["of"] = seq
		} else {
			w.closes = append(w.closes, &pendingClose{peer: b.Addr, rec: r, left: outcomeLinkWindow})
			return nil
		}
	}
	delete(w.disc, b.Addr)
	return w.write(r)
}

// checked notes the received frame seq of key that the core checked, the
// first one for the key.
func (w *r01Writer) checked(key types.Hash, seq uint64) {
	if _, ok := w.core[key]; !ok {
		w.core[key] = seq
	}
}

// disconnected notes that the frame seq of peer ended DISCONNECT and gives
// it to the first close waiting for one.
func (w *r01Writer) disconnected(peer types.Address, seq uint64) error {
	for i, p := range w.closes {
		if p.peer == peer {
			p.rec["of"] = seq
			w.closes = append(w.closes[:i], w.closes[i+1:]...)
			return w.write(p.rec)
		}
	}
	w.disc[peer] = seq
	return nil
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
	// A record with a size kept only the size (the frame was too large to
	// keep); otherwise the payload, possibly empty, is the frame's.
	if b.Size > 0 && uint64(len(b.Payload)) != b.Size {
		r["size"] = b.Size
	} else {
		r["size"] = len(b.Payload)
		sum, err := w.payload(b.Payload)
		if err != nil {
			return err
		}
		r["payload_sha256"] = sum
	}
	r["dedup_key"] = hexHash(b.DedupKey)
	if b.Dir == journal.In {
		r["outcome"] = inOutcome(b.Offer)
		if b.Engine != "" {
			r["engine"] = b.Engine
		}
		if b.Dedup != nil {
			r["dedup"] = map[string]bool{"known_hit": b.Dedup.Known, "peer_recent_hit": b.Dedup.PeerRecent}
		}
	} else {
		if b.Write != "" && b.Write != transport.WriteOK {
			r["write_error"] = b.Write
		}
		if b.Cause != "" {
			r["cause"] = b.Cause
		}
		switch {
		case b.RelayOf != 0:
			r["relay_of"] = b.RelayOf
		case b.Cause == event.CauseRelay && w.lastIn[b.DedupKey] != 0:
			// A relay sends the received bytes unchanged: the same key.
			r["relay_of"] = w.lastIn[b.DedupKey]
		case b.Cause == event.CauseRelay && b.DedupKey != (types.Hash{}):
			w.relays = append(w.relays, &pendingRelay{key: b.DedupKey, rec: r, left: outcomeLinkWindow})
			return w.tick()
		}
	}
	if err := w.write(r); err != nil {
		return err
	}
	if b.Dir == journal.In && b.DedupKey != (types.Hash{}) {
		w.lastIn[b.DedupKey] = seq
		if err := w.relayed(b.DedupKey, seq); err != nil {
			return err
		}
	}
	if p := w.peers[b.PeerIdx]; b.Dir == journal.In && b.Offer == transport.OfferFrameDisconnect && p != nil {
		if err := w.disconnected(p.Addr, seq); err != nil {
			return err
		}
	}
	if p := w.peers[b.PeerIdx]; b.Dir == journal.In && b.Offer == transport.OfferQueued && p != nil {
		if err := w.link(linkKey{peer: p.Addr, key: b.DedupKey}, seq); err != nil {
			return err
		}
	}
	return w.tick()
}

// relayed gives the waiting relays of key to the received frame seq.
func (w *r01Writer) relayed(key types.Hash, seq uint64) error {
	kept := w.relays[:0]
	for _, p := range w.relays {
		if p.key != key {
			kept = append(kept, p)
			continue
		}
		p.rec["relay_of"] = seq
		if err := w.write(p.rec); err != nil {
			return err
		}
	}
	w.relays = kept
	return nil
}

// link gives the waiting outcomes of k to the received frame seq, which the
// receiver took. An outcome decided while the frame was offered settles
// it: that outcome alone is the frame's, and the frame is not a target of
// later outcomes. Otherwise the outcomes the core journaled before the
// frame belong to it, and so do later ones until the next copy. Linked
// outcomes follow the frame in the file and keep their own seq.
func (w *r01Writer) link(k linkKey, seq uint64) error {
	settled := slices.IndexFunc(w.wait, func(o *pendingOutcome) bool { return o.key == k && o.atOffer })
	kept := w.wait[:0]
	for i, o := range w.wait {
		if o.key != k || (settled >= 0 && i != settled) {
			kept = append(kept, o)
			continue
		}
		o.rec["of"] = seq
		if o.rec["via"] == "direct" && o.rec["check"] != "prefilter" {
			w.checked(k.key, seq)
		}
		if err := w.write(o.rec); err != nil {
			return err
		}
		if o.rec["outcome"] == string(event.Disconnect) {
			if err := w.disconnected(k.peer, seq); err != nil {
				return err
			}
		}
	}
	w.wait = kept
	if settled < 0 {
		w.last[k] = seq
	}
	return nil
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
	case b.Via == "backlog" && b.Peer == (types.Address{}):
		// The core replays a backlog message without its peer.
		r["of"] = nil
		if f := w.core[b.DedupKey]; f != 0 {
			r["of"] = f
		} else {
			w.res.Unlinked++
		}
	case !b.AtOffer && w.last[k] != 0:
		r["of"] = w.last[k]
		if b.Via == "direct" && b.Check != "prefilter" {
			w.checked(b.DedupKey, w.last[k])
		}
		if b.Outcome == event.Disconnect {
			if err := w.write(r); err != nil {
				return err
			}
			if err := w.disconnected(b.Peer, w.last[k]); err != nil {
				return err
			}
			return w.tick()
		}
	default:
		r["of"] = nil
		w.wait = append(w.wait, &pendingOutcome{key: k, rec: r, left: outcomeLinkWindow, atOffer: b.AtOffer})
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
