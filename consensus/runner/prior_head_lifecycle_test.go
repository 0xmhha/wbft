package runner

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/types"
)

func TestBindPriorHeadPreparedGracefulCloseOpen(t *testing.T) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 1)
	n.opts.Improvements = n.opts.Improvements.With(consensus.BindPriorHead)
	n.boot()
	t.Cleanup(func() {
		_ = n.r.Close()
		_ = n.log.Close()
	})
	b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	reachPrepared(t, n, b)
	before, source := n.r.Vars(), n.r.Snapshot().PriorSource.Copy()
	if before.State != consensus.Prepared || before.LockedRound == nil || len(before.Certificate) != 3 || source == nil {
		t.Fatal("actual prepared quorum or prior source missing")
	}
	commit := bytes.Clone(n.net.own(codec.CodeCommit)[0])
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.log.Close(); err != nil {
		t.Fatal(err)
	}
	n.net.sent = nil
	n.boot()
	after, replay := n.r.Vars(), n.r.LastReplay()
	if !replay.Replayed || replay.Stopped != "" || replay.Records == 0 || after.State != consensus.Prepared || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(source, n.r.Snapshot().PriorSource) {
		t.Fatal("normal same-height reopen changed prepared state", replay, before, after)
	}
	resent := n.net.own(codec.CodeCommit)
	if len(resent) != 1 || !bytes.Equal(resent[0], commit) {
		t.Fatal("persisted own COMMIT bytes changed")
	}
	old, err := codec.DecodeMessage(codec.CodeCommit, commit)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := n.signer.SignVote(privval.VoteRequest{Msg: &codec.Message{Code: codec.CodeCommit, View: view(10, 0), Digest: codec.BlockHash(b.Header)}, SealData: codec.SealData(b.Header, 0, types.CommitSeal)})
	if err != nil || !reused.Reused || !bytes.Equal(reused.Signature, old.Signature) || !bytes.Equal(reused.Seal, old.Seal) {
		t.Fatal("reopened file signer did not reuse the persisted vote", err)
	}
	n.advance(2 * time.Second)
	rcs := n.net.own(codec.CodeRoundChange)
	if len(rcs) != 1 {
		t.Fatal("restored round timer did not retain progress")
	}
	rc, err := codec.DecodeMessage(codec.CodeRoundChange, rcs[0])
	if err != nil || rc.PreparedRound == nil || rc.PreparedRound.Cmp(*before.LockedRound) != 0 || rc.PreparedDigest != codec.BlockHash(b.Header) || len(rc.Prepares) != 3 {
		t.Fatal("normal round change lost its prepared certificate", err)
	}
}

func TestBindPriorHeadProfileMismatchRefused(t *testing.T) {
	for _, mode := range []string{"disabled", "disabled-without-replay", "enabled-without-replay", "enabled-without-wal"} {
		t.Run(mode, func(t *testing.T) {
			k := newKeys(t, 4)
			n := newTNode(t, k, 1)
			n.opts.Improvements = n.opts.Improvements.With(consensus.BindPriorHead)
			n.boot()
			if err := n.r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := n.log.Close(); err != nil {
				t.Fatal(err)
			}
			before, _, err := wal.ReadAll(n.fs, "/wal")
			if err != nil || len(before) == 0 || before[0].Format != priorHeadFormat {
				t.Fatal("normal format-three WAL missing", err)
			}
			log, _, err := wal.Open(n.fs, "/wal", wal.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			cfg := Config{Core: n.opts, ReplayWAL: true, Manual: true}
			deps := Deps{Chain: n.chain, App: n.app, Clock: n.clock, WAL: log, Signer: n.signer}
			if mode == "disabled" || mode == "disabled-without-replay" {
				cfg.Core.Improvements &^= consensus.ImprovementSet(0).With(consensus.BindPriorHead)
			}
			if mode == "disabled-without-replay" || mode == "enabled-without-replay" {
				cfg.ReplayWAL = false
			}
			if mode == "enabled-without-wal" {
				deps.WAL = nil
			}
			r, err := New(cfg, deps)
			if err == nil {
				defer func() { _ = r.Close() }()
				err = r.Start(context.Background(), types.HeightFromUint64(10))
			}
			if !errors.Is(err, errPriorHeadWAL) {
				t.Fatal("supported build accepted mismatching operator profile", mode, err)
			}
			after, _, err := wal.ReadAll(n.fs, "/wal")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("profile refusal rewrote the normal WAL", err)
			}
		})
	}
}
