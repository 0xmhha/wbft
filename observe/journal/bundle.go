package journal

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

// A journal bundle (observe.md 11.7, analyzer replay.md 4) is one tar file
// holding manifest.json and the journal segments (with their index files)
// that cover a range of heights, from a few heights earlier (the warm-up)
// so that a re-execution can start before the compared range. The analyzer
// takes it as a dataset input; wbft-replay replays it when it starts at the
// start of a writer run (starts_at_run_start), since the core is rebuilt
// from the start step of an engine run.

// BundleFormat names the bundle format (manifest field format).
const BundleFormat = "wbft-journal-bundle/1"

// DefaultBundleWarmup is the number of heights before From a bundle holds
// by default.
const DefaultBundleWarmup = 2

// BundleOptions select the heights of a bundle: the segments whose steps
// decide heights in [From, To] (nil: no bound), and Warmup heights before
// From.
type BundleOptions struct {
	From, To *types.Height
	Warmup   uint64
}

// BundleManifest is manifest.json.
type BundleManifest struct {
	Format string `json:"format"`
	// Node is the identity of the writer of the first segment.
	Node BundleNode `json:"node"`
	// WBFTCommit is the wbft version that wrote the first segment.
	WBFTCommit string `json:"wbft_commit"`
	// Runs lists the writer runs in the bundle, in order.
	Runs []string `json:"runs"`
	// Heights is the requested range and what the segments hold.
	Heights BundleHeights `json:"heights"`
	// StartsAtRunStart reports that the first segment is the first of its
	// writer run, so that the bundle holds the start of every engine run.
	StartsAtRunStart bool `json:"starts_at_run_start"`
	// Gaps are the records the writer dropped inside the bundle.
	Gaps  []BundleGap  `json:"gaps"`
	Files []BundleFile `json:"files"`
}

type BundleNode struct {
	Self         string `json:"self"`
	BLSPublicKey string `json:"bls_public_key,omitempty"`
	Mode         string `json:"mode"`
	WireOffset   uint64 `json:"wire_offset"`
	ChainID      string `json:"chain_id,omitempty"`
	GenesisHash  string `json:"genesis_hash"`
}

type BundleHeights struct {
	From   string `json:"from,omitempty"` // requested, decimal
	To     string `json:"to,omitempty"`
	Warmup uint64 `json:"warmup"`
	// FirstHead and LastHead bound the heads the core read in the steps of
	// the bundle (the height being decided is head + 1).
	FirstHead string `json:"first_head,omitempty"`
	LastHead  string `json:"last_head,omitempty"`
}

type BundleGap struct {
	Segment     string `json:"segment"`
	Dropped     uint64 `json:"dropped"`
	FirstMonoNs int64  `json:"first_mono_ns"`
	LastMonoNs  int64  `json:"last_mono_ns"`
}

type BundleFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// segInfo is what the bundle needs to know of one segment.
type segInfo struct {
	seg        wal.SegmentInfo
	first      *SegmentRec // its segment record
	minH, maxH *types.Height
	gaps       []BundleGap
}

// WriteBundle writes the bundle of the journal in dir to w as a tar file
// and returns its manifest. A nil fs is the operating system.
func WriteBundle(fs fsys.FS, dir string, w io.Writer, opt BundleOptions) (*BundleManifest, error) {
	if fs == nil {
		fs = fsys.OS{}
	}
	from, to, warmup := opt.From, opt.To, opt.Warmup
	segs, err := wal.Segments(fs, dir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("no journal segments in %s", dir)
	}
	infos := make([]*segInfo, len(segs))
	byIndex := map[uint64]*segInfo{}
	for i, s := range segs {
		infos[i] = &segInfo{seg: s}
		byIndex[s.Index] = infos[i]
	}
	r, err := OpenReader(fs, dir)
	if err != nil {
		return nil, err
	}
	for {
		rec, pos, err := r.NextAt()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("journal: bundle: the journal reads only up to a damaged record: %w", err)
		}
		si := byIndex[pos.Segment]
		if si == nil {
			continue
		}
		switch b := rec.Body.(type) {
		case *SegmentRec:
			if si.first == nil {
				si.first = b
			}
		case *StepRec:
			h := b.HeadNumber
			if si.minH == nil || h.Cmp(*si.minH) < 0 {
				si.minH = &h
			}
			if si.maxH == nil || h.Cmp(*si.maxH) > 0 {
				si.maxH = &h
			}
		case *GapRec:
			si.gaps = append(si.gaps, BundleGap{Segment: si.seg.Name, Dropped: b.Dropped,
				FirstMonoNs: int64(b.FirstMono), LastMonoNs: int64(b.LastMono)})
		}
	}

	// The heads that cover the range: head + 1 is the height decided.
	var lo, hi *types.Height
	if from != nil {
		l := types.Height{}
		if f, ok := from.Sub(types.HeightFromUint64(warmup + 1)); ok {
			l = f
		}
		lo = &l
	}
	if to != nil {
		h := types.Height{}
		if t, ok := to.Sub(types.HeightFromUint64(1)); ok {
			h = t
		}
		hi = &h
	}
	first, last := -1, -1
	for i, si := range infos {
		if si.minH == nil {
			continue
		}
		if (lo == nil || si.maxH.Cmp(*lo) >= 0) && (hi == nil || si.minH.Cmp(*hi) <= 0) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		return nil, errors.New("journal: bundle: no segment holds steps in the requested heights")
	}
	// Segments without steps between chosen ones belong to the range.
	chosen := infos[first : last+1]
	head := chosen[0].first
	if head == nil {
		return nil, fmt.Errorf("journal: bundle: segment %s has no segment record", chosen[0].seg.Name)
	}
	m := &BundleManifest{Format: BundleFormat, WBFTCommit: head.Commit, Runs: []string{}, Gaps: []BundleGap{},
		Node: BundleNode{Self: "0x" + hex.EncodeToString(head.Self[:]), Mode: head.Mode, WireOffset: head.WireOffset,
			GenesisHash: "0x" + hex.EncodeToString(head.GenesisHash[:])},
		Heights: BundleHeights{Warmup: warmup}}
	if from != nil {
		m.Heights.From = from.String()
	}
	if to != nil {
		m.Heights.To = to.String()
	}
	if len(head.BLSPublicKey) > 0 {
		m.Node.BLSPublicKey = "0x" + hex.EncodeToString(head.BLSPublicKey)
	}
	if head.ChainID != nil {
		m.Node.ChainID = head.ChainID.String()
	}
	// The bundle starts at the start of a run when the segment before it
	// belongs to another run (or there is none).
	m.StartsAtRunStart = first == 0 || infos[first-1].first == nil || infos[first-1].first.Run != head.Run
	var minH, maxH *types.Height
	for _, si := range chosen {
		if si.first != nil && (len(m.Runs) == 0 || m.Runs[len(m.Runs)-1] != si.first.Run) {
			m.Runs = append(m.Runs, si.first.Run)
		}
		if si.minH != nil && (minH == nil || si.minH.Cmp(*minH) < 0) {
			minH = si.minH
		}
		if si.maxH != nil && (maxH == nil || si.maxH.Cmp(*maxH) > 0) {
			maxH = si.maxH
		}
		m.Gaps = append(m.Gaps, si.gaps...)
	}
	m.Heights.FirstHead, m.Heights.LastHead = minH.String(), maxH.String()

	// The manifest lists the hashes of the files before them: hash every
	// file first, then write the tar reading each file again, one at a
	// time (a segment is at most SegmentBytes).
	var names []string
	for _, si := range chosen {
		names = append(names, si.seg.Name)
		if _, ok := readIndex(fs, dir, si.seg.Name); ok {
			names = append(names, si.seg.Name+".idx")
		}
	}
	for _, n := range names {
		b, err := fs.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256(b)
		m.Files = append(m.Files, BundleFile{Name: n, Size: int64(len(b)), SHA256: hex.EncodeToString(s[:])})
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(w)
	add := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	err = add("manifest.json", append(mb, '\n'))
	for i, n := range names {
		if err != nil {
			break
		}
		var b []byte
		if b, err = fs.ReadFile(filepath.Join(dir, n)); err != nil {
			break
		}
		// A segment being written may have grown since it was hashed: the
		// bundle holds the bytes the manifest describes.
		if int64(len(b)) > m.Files[i].Size {
			b = b[:m.Files[i].Size]
		}
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != m.Files[i].SHA256 {
			err = fmt.Errorf("journal: bundle: %s changed while it was bundled", n)
			break
		}
		err = add(n, b)
	}
	if err == nil {
		err = tw.Close()
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ReadBundle extracts a bundle from r into the directory dst, which it
// creates, and returns its manifest. It refuses a bundle whose first
// entry is not the manifest, an entry the manifest does not list or lists
// with another size or hash, a path outside dst, and a listed file that is
// missing. A nil fs is the operating system.
func ReadBundle(r io.Reader, fs fsys.FS, dst string) (*BundleManifest, error) {
	if fs == nil {
		fs = fsys.OS{}
	}
	tr := tar.NewReader(r)
	h, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("journal: bundle: %w", err)
	}
	if h.Name != "manifest.json" {
		return nil, fmt.Errorf("journal: bundle: first entry %q, want manifest.json", h.Name)
	}
	mb, err := io.ReadAll(io.LimitReader(tr, 1<<20))
	if err != nil {
		return nil, err
	}
	var m BundleManifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, fmt.Errorf("journal: bundle: manifest: %w", err)
	}
	if m.Format != BundleFormat {
		return nil, fmt.Errorf("journal: bundle: format %q, want %q", m.Format, BundleFormat)
	}
	want := map[string]BundleFile{}
	for _, f := range m.Files {
		want[f.Name] = f
	}
	if err := fs.MkdirAll(dst, 0o700); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("journal: bundle: %w", err)
		}
		f, ok := want[h.Name]
		if !ok || seen[h.Name] || filepath.Base(h.Name) != h.Name || !IsJournalFile(h.Name) {
			return nil, fmt.Errorf("journal: bundle: unexpected entry %q", h.Name)
		}
		if h.Size != f.Size {
			return nil, fmt.Errorf("journal: bundle: %s has %d bytes, the manifest %d", h.Name, h.Size, f.Size)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != f.SHA256 {
			return nil, fmt.Errorf("journal: bundle: %s does not match its hash in the manifest", h.Name)
		}
		if err := fsys.WriteFileAtomic(fs, dst, filepath.Join(dst, h.Name), b, 0o600); err != nil {
			return nil, err
		}
		seen[h.Name] = true
	}
	for _, f := range m.Files {
		if !seen[f.Name] {
			return nil, fmt.Errorf("journal: bundle: %s is missing", f.Name)
		}
	}
	return &m, nil
}
