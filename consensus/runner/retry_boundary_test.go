package runner

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/internal/fsys"
	"github.com/0xmhha/wbft/types"
)

func TestNormalRetryWALHandshakeConfiguration(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.opts.RoundChangeRetry = &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
	r := &Runner{cfg: Config{Core: n.opts, ReplayWAL: true}}
	head := block(t, 10, 1, k.addrs[0], types.Hash{9}).Header
	b := boundaryRec{From: head.Number.AddUint64(1), Head: head, Validators: k.vs}
	base, err := encodeBoundary(walEndHeight, b)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := r.encodeRunnerBoundary(walEndHeight, b)
	if err != nil {
		t.Fatal(err)
	}
	inner, maximum, improvements, err := decodeRetryBoundary(wrapped)
	if err != nil || inner.Format != base.Format || !bytes.Equal(inner.Body, base.Body) || maximum != 8000 || improvements != uint64(n.opts.Improvements) {
		t.Fatal("retry profile did not preserve original boundary", err)
	}
	fs := fsys.NewMem()
	log, _, err := wal.Open(fs, "/wal", wal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.AppendSync(wrapped); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := InspectWALForConfig(fs, "/wal", r.cfg)
	if err != nil || st.LastEnd == nil || st.LastEnd.Cmp(head.Number) != 0 {
		t.Fatal("handshake skipped the normal format-four end boundary", st, err)
	}
	if _, err := InspectWAL(fs, "/wal"); !errors.Is(err, errRoundChangeRetryWAL) {
		t.Fatal("legacy handshake accepted undeclared retry profile", err)
	}
	for _, mode := range []string{"disabled", "different-maximum", "different-improvements", "replay-disabled"} {
		cfg := r.cfg
		cfg.Core.RoundChangeRetry = cfg.Core.RoundChangeRetry.Copy()
		switch mode {
		case "disabled":
			cfg.Core.RoundChangeRetry = nil
		case "different-maximum":
			cfg.Core.RoundChangeRetry.MaxIntervalMs++
		case "different-improvements":
			cfg.Core.Improvements = cfg.Core.Improvements.With(consensus.CancelStaleRetries)
		case "replay-disabled":
			cfg.ReplayWAL = false
		}
		if _, err := InspectWALForConfig(fs, "/wal", cfg); !errors.Is(err, errRoundChangeRetryWAL) {
			t.Fatal("configuration mismatch reached application handshake", mode, err)
		}
	}
}

// Normal boundary construction and configuration matching only: no live log
// is damaged or modified. Independent deferred replay remains separate.
func TestNormalRetryWALWrappedProfileMatrix(t *testing.T) {
	past, next := newKeys(t, 4), newKeys(t, 5)
	head := block(t, 10, 1, past.addrs[0], types.Hash{9}).Header
	for _, prior := range []bool{false, true} {
		for _, deferred := range []bool{false, true} {
			t.Run(fmt.Sprintf("prior=%t/deferred=%t", prior, deferred), func(t *testing.T) {
				n := newTNode(t, past, 1)
				n.opts.RoundChangeRetry = &consensus.RoundChangeRetryOptions{MaxIntervalMs: 8000}
				if prior {
					n.opts.Improvements = n.opts.Improvements.With(consensus.BindPriorHead)
				}
				r := &Runner{cfg: Config{Core: n.opts, ReplayWAL: true}}
				if deferred {
					limits := NextHeightLimits{Entries: 8, Bytes: 1 << 20, PerPeer: 4, PerSource: 4}
					r.cfg.NextHeight, r.nextHeight = &limits, newNextHeightPool(limits)
				}
				b := boundaryRec{From: head.Number.AddUint64(1), Head: head, Validators: next.vs, Replayed: true}
				if prior {
					var err error
					b.PriorSource, err = consensus.NewPriorHeadSource(head, past.vs)
					if err != nil {
						t.Fatal(err)
					}
				}
				wrapped, err := r.encodeRunnerBoundary(walEndHeight, b)
				if err != nil {
					t.Fatal(err)
				}
				inner, maximum, mask, err := decodeRetryBoundary(wrapped)
				if err != nil || maximum != 8000 || mask != uint64(n.opts.Improvements) {
					t.Fatal("wrapper declaration changed", err)
				}
				off := &Runner{cfg: r.cfg, nextHeight: r.nextHeight}
				off.cfg.Core.RoundChangeRetry = nil
				base, err := off.encodeRunnerBoundary(walEndHeight, b)
				if err != nil || inner.Format != base.Format || inner.Kind != base.Kind || !bytes.Equal(inner.Body, base.Body) {
					t.Fatal("inner profile bytes changed", err)
				}
				decoded, pending, err := decodeRunnerBoundary(wrapped)
				if err != nil || decoded.Validators.Len() != 5 || (pending != nil) != deferred || (decoded.PriorSource != nil) != prior {
					t.Fatal("wrapped profile lost", err)
				}
				if prior && (decoded.PriorSource.Validators.Len() != 4 || decoded.PriorSource.ValidateHead(head) != nil) {
					t.Fatal("historical authority replaced by successor")
				}
				if pending != nil && pending.Limits != *r.cfg.NextHeight {
					t.Fatal("deferred limits changed")
				}
				fs := fsys.NewMem()
				log, _, err := wal.Open(fs, "/wal", wal.Options{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := log.AppendSync(wrapped); err != nil {
					t.Fatal(err)
				}
				if err := log.Close(); err != nil {
					t.Fatal(err)
				}
				state, err := InspectWALForConfig(fs, "/wal", r.cfg)
				if err != nil || state.LastEnd == nil || state.LastEnd.Cmp(head.Number) != 0 {
					t.Fatal("wrapped handshake skipped end height", err)
				}
				if _, err := InspectWALForConfig(fs, "/wal", off.cfg); err == nil {
					t.Fatal("disabled policy accepted new wrapper")
				}
				if deferred {
					mismatch := r.cfg
					limits := *mismatch.NextHeight
					limits.Entries++
					mismatch.NextHeight = &limits
					if _, err := InspectWALForConfig(fs, "/wal", mismatch); err == nil {
						t.Fatal("changed deferred limits accepted")
					}
				}
			})
		}
	}
}
