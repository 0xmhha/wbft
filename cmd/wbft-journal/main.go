// Command wbft-journal inspects and maintains a message journal directory
// (observe/journal, observe.md 11.7) without stopping the node that writes
// it: a segment being written is read up to its last complete record.
//
//	wbft-journal stat   --dir DIR
//	wbft-journal verify --dir DIR
//	wbft-journal prune  --dir DIR [--keep-heights N] [--max-bytes S] [--head H]
//	wbft-journal export --dir DIR --out OUT [--format bundle|r01] [--from H1] [--to H2] [--warmup K]
//
// export --format bundle (the default) writes the journal bundle that the
// analyzer and wbft-replay read: a tar file of the segments that cover the
// heights, with a manifest (bundle.go). export --format r01 writes the R-01
// frame dump that wbft-inspector reads into the directory OUT (export.go).
//
// Every command prints one JSON object. verify exits with 1 when it finds a
// problem; every command exits with 2 on a usage or I/O error.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func main() {
	os.Exit(run(os.Args[1:], fsys.OS{}, os.Stdout, os.Stderr))
}

const usage = "usage: wbft-journal stat|verify|prune|export --dir DIR [flags]"

func run(args []string, fs fsys.FS, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	set := flag.NewFlagSet("wbft-journal "+args[0], flag.ContinueOnError)
	set.SetOutput(stderr)
	dir := set.String("dir", "", "journal directory")
	keep := set.Uint64("keep-heights", journal.DefaultOptions("").KeepHeights, "prune: keep the segments that hold heights >= head - N (0: no height rule)")
	maxBytes := set.Int64("max-bytes", journal.DefaultOptions("").MaxBytes, "prune: then remove the oldest segments while the total is above S bytes (0: no size rule)")
	head := set.String("head", "", "prune: the head height (decimal); default: the highest head in the index files")
	out := set.String("out", "", "export: output file (bundle; must not exist) or directory (r01; its frame files must not exist)")
	format := set.String("format", "bundle", "export: bundle (journal segments and manifest, a tar file) or r01 (the frame dump)")
	warmup := set.Uint64("warmup", journal.DefaultBundleWarmup, "export bundle: heights before --from to include")
	from := set.String("from", "", "export: first height (decimal) of the records")
	to := set.String("to", "", "export: last height (decimal) of the records")
	if err := set.Parse(args[1:]); err != nil {
		return 2
	}
	if *dir == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var res any
	code := 0
	var err error
	switch args[0] {
	case "stat":
		res, err = stat(fs, *dir)
	case "verify":
		var v *verifyResult
		v, err = verify(fs, *dir)
		if v != nil && len(v.Problems) > 0 {
			code = 1
		}
		res = v
	case "prune":
		res, err = prune(fs, *dir, *keep, *maxBytes, *head)
	case "export":
		switch {
		case *out == "":
			err = errors.New("export: --out is required")
		case *format == "bundle":
			res, err = exportBundle(fs, *dir, *out, *from, *to, *warmup)
		case *format == "r01":
			res, err = exportR01(fs, *dir, *out, *from, *to)
		default:
			err = fmt.Errorf("export: unknown format %q (bundle or r01)", *format)
		}
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "wbft-journal:", err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(stderr, "wbft-journal:", err)
		return 2
	}
	return code
}

// segmentStat is what stat reports for one segment.
type segmentStat struct {
	Name    string           `json:"name"`
	Size    int64            `json:"size"`
	Closed  bool             `json:"closed"` // it has an index file
	Records map[string]int64 `json:"records"`
	// FirstJSeq and LastJSeq bound the record numbers in the segment.
	FirstJSeq uint64 `json:"first_jseq"`
	LastJSeq  uint64 `json:"last_jseq"`
	// MinHead and MaxHead are the heads the core read in its steps
	// (decimal); empty without a step record.
	MinHead string `json:"min_head,omitempty"`
	MaxHead string `json:"max_head,omitempty"`
}

// runStat describes one writer run (a node process) found in the journal.
type runStat struct {
	Run        string        `json:"run"`
	Self       types.Address `json:"self"`
	Mode       string        `json:"mode"`
	Commit     string        `json:"commit"`
	EngineRuns []uint64      `json:"engine_runs"`
}

type statResult struct {
	Dir      string           `json:"dir"`
	Segments []*segmentStat   `json:"segments"`
	Bytes    int64            `json:"bytes"`
	Records  map[string]int64 `json:"records"`
	Runs     []*runStat       `json:"runs"`
	// Dropped is the number of records the writer dropped (gap records).
	Dropped uint64 `json:"dropped"`
	// End is "eof", or the error that stopped the reading.
	End string `json:"end"`
}

// scan reads the journal in order and calls f for every record; it returns
// the error that ended the reading, nil at the end.
func scan(fs fsys.FS, dir string, f func(journal.Record, wal.Position)) error {
	r, err := journal.OpenReader(fs, dir)
	if err != nil {
		return err
	}
	for {
		rec, pos, err := r.NextAt()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		f(rec, pos)
	}
}

func stat(fs fsys.FS, dir string) (*statResult, error) {
	segs, err := wal.Segments(fs, dir)
	if err != nil {
		return nil, err
	}
	res := &statResult{Dir: dir, Records: map[string]int64{}, Runs: []*runStat{}, Segments: []*segmentStat{}}
	byIndex := map[uint64]*segmentStat{}
	heads := map[uint64][2]*types.Height{}
	for _, s := range segs {
		ss := &segmentStat{Name: s.Name, Size: s.Size, Records: map[string]int64{}}
		_, ss.Closed = journal.ReadIndex(fs, dir, s.Name)
		res.Segments = append(res.Segments, ss)
		byIndex[s.Index] = ss
		res.Bytes += s.Size
	}
	var cur *runStat
	end := scan(fs, dir, func(rec journal.Record, pos wal.Position) {
		ss := byIndex[pos.Segment]
		if ss == nil {
			return
		}
		k := rec.Kind.String()
		ss.Records[k]++
		res.Records[k]++
		if ss.FirstJSeq == 0 {
			ss.FirstJSeq = rec.JSeq
		}
		ss.LastJSeq = rec.JSeq
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
			if cur == nil || cur.Run != b.Run {
				cur = &runStat{Run: b.Run, Self: b.Self, Mode: b.Mode, Commit: b.Commit, EngineRuns: []uint64{}}
				res.Runs = append(res.Runs, cur)
			}
		case *journal.StepRec:
			if cur != nil && !slices.Contains(cur.EngineRuns, b.EngineRun) {
				cur.EngineRuns = append(cur.EngineRuns, b.EngineRun)
			}
			h := b.HeadNumber
			mm := heads[pos.Segment]
			if mm[0] == nil || h.Cmp(*mm[0]) < 0 {
				mm[0] = &h
			}
			if mm[1] == nil || h.Cmp(*mm[1]) > 0 {
				mm[1] = &h
			}
			heads[pos.Segment] = mm
		case *journal.GapRec:
			res.Dropped += b.Dropped
		}
	})
	for i, mm := range heads { //wbft:unordered each entry sets its own segment
		if mm[0] != nil {
			byIndex[i].MinHead, byIndex[i].MaxHead = mm[0].String(), mm[1].String()
		}
	}
	res.End = "eof"
	if end != nil {
		res.End = end.Error()
	}
	return res, nil
}

type verifyResult struct {
	Dir      string   `json:"dir"`
	Segments int      `json:"segments"`
	Records  int64    `json:"records"`
	Problems []string `json:"problems"`
}

// verify reads every record and checks that the journal reads to its end
// (frame checksums and record encodings), that every segment starts with
// a segment record, that record numbers increase by one within a writer
// run and restart at 1 with a new run (the first record read may follow
// pruned segments), and that every msg record with a payload carries the
// payload's dedup key.
func verify(fs fsys.FS, dir string) (*verifyResult, error) {
	segs, err := wal.Segments(fs, dir)
	if err != nil {
		return nil, err
	}
	res := &verifyResult{Dir: dir, Segments: len(segs), Problems: []string{}}
	add := func(format string, args ...any) { res.Problems = append(res.Problems, fmt.Sprintf(format, args...)) }
	var last uint64
	var run string
	seen := map[uint64]bool{}
	end := scan(fs, dir, func(rec journal.Record, pos wal.Position) {
		res.Records++
		name := fmt.Sprintf("segment %020d offset %d", pos.Segment, pos.Offset)
		first := !seen[pos.Segment]
		seen[pos.Segment] = true
		s, isSeg := rec.Body.(*journal.SegmentRec)
		if first && !isSeg {
			add("%s: the segment starts with a %s record, not a segment record", name, rec.Kind)
		}
		// The first record read may follow pruned segments; a new writer run
		// numbers from 1.
		want := last + 1
		if isSeg && s.Run != run {
			if res.Records > 1 {
				want = 1
			} else {
				want = rec.JSeq
			}
			run = s.Run
		}
		if rec.JSeq != want {
			add("%s: jseq %d, want %d", name, rec.JSeq, want)
		}
		last = rec.JSeq
		if m, ok := rec.Body.(*journal.MsgRec); ok && len(m.Payload) > 0 && m.DedupKey != codec.DedupKey(m.Payload) {
			add("%s: msg jseq %d: dedup key %x is not that of its payload", name, rec.JSeq, m.DedupKey)
		}
	})
	if end != nil {
		add("reading stopped: %v", end)
	}
	return res, nil
}

type pruneResult struct {
	Dir     string   `json:"dir"`
	Head    string   `json:"head"`
	Removed []string `json:"removed"`
	Bytes   int64    `json:"bytes"`
}

// prune removes closed segments by the journal's rules (journal.Prune). The
// last segment is kept: its writer may still be appending to it.
func prune(fs fsys.FS, dir string, keep uint64, maxBytes int64, headArg string) (*pruneResult, error) {
	var head types.Height
	if headArg != "" {
		v, ok := new(big.Int).SetString(headArg, 10)
		if !ok {
			return nil, fmt.Errorf("--head %q is not a decimal height", headArg)
		}
		h, err := types.HeightFromBig(v)
		if err != nil {
			return nil, fmt.Errorf("--head: %w", err)
		}
		head = h
	}
	segs, err := wal.Segments(fs, dir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return &pruneResult{Dir: dir, Removed: []string{}}, nil
	}
	if headArg == "" {
		found := false
		for _, s := range segs {
			ix, ok := journal.ReadIndex(fs, dir, s.Name)
			if !ok || ix.MaxHeight == nil {
				continue
			}
			v, ok := new(big.Int).SetString(*ix.MaxHeight, 10)
			if !ok {
				continue
			}
			if h, err := types.HeightFromBig(v); err == nil && (!found || h.Cmp(head) > 0) {
				head, found = h, true
			}
		}
		if !found && keep > 0 {
			return nil, errors.New("no index file names a head; pass --head")
		}
	}
	opt := journal.Options{KeepHeights: keep, MaxBytes: maxBytes}
	r, err := journal.Prune(fs, dir, head, opt, segs[len(segs)-1].Index)
	if err != nil {
		return nil, err
	}
	removed := r.Removed
	if removed == nil {
		removed = []string{}
	}
	return &pruneResult{Dir: dir, Head: head.String(), Removed: removed, Bytes: r.Bytes}, nil
}
