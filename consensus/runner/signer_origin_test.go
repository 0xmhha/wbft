package runner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

// A normal process close/reopen uses two independent diagnostic writers.
// No actor input, signed message, source record, or WAL byte is modified.
type explicitOriginLifetime struct {
	runner                                *Runner
	log                                   *wal.Log
	writer                                *journal.FileWriter
	runnerClosed, logClosed, writerClosed bool
}

func TestSignerOriginSeparateWriterHandoffs(t *testing.T) {
	for _, mode := range []struct {
		name   string
		offset uint64
	}{{"standalone", 0x10}, {"embedded", 0}} {
		t.Run(mode.name, func(t *testing.T) { runSignerOriginSeparateWriterHandoffs(t, mode.name, mode.offset) })
	}
}

func runSignerOriginSeparateWriterHandoffs(t *testing.T, mode string, offset uint64) {
	k := newKeys(t, 4)
	n := newTNode(t, k, 0)
	n.noJournal = true
	n.chain.head.Time = uint64(n.clock.Now().Unix()) - 1
	config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
	limits := wal.ReadSourceLimits{Frames: 1024, Bytes: 8 << 20}
	genesis := codec.BlockHash(n.chain.head)
	var active *explicitOriginLifetime
	openWriter := func(run, dir string) (*explicitOriginLifetime, *restoreRecorder) {
		writer, err := journal.Open(journal.Options{FS: n.jfs, Dir: dir, Synchronous: true}, journal.Identity{Self: n.opts.Self, ChainID: big.NewInt(8282), GenesisHash: genesis, Mode: mode, WireOffset: offset, BLSPublicKey: k.bls[0].PublicKey().Bytes(), Run: run, Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), TimerTrace: journal.TimerTraceVersion}})
		if err != nil {
			t.Fatal(err)
		}
		life := &explicitOriginLifetime{writer: writer}
		active = life
		// Closed first-process handles are retained in life, not in the new process.
		n.r, n.log = nil, nil
		t.Cleanup(func() {
			r, log := life.runner, life.log
			if active == life {
				if r == nil {
					r = n.r
				}
				if log == nil {
					log = n.log
				}
			}
			if r != nil && !life.runnerClosed {
				if e := r.Close(); e != nil {
					t.Error(e)
				} else {
					life.runnerClosed = true
				}
			}
			if log != nil && !life.logClosed {
				if e := log.Close(); e != nil {
					t.Error(e)
				} else {
					life.logClosed = true
				}
			}
			if !life.writerClosed {
				if e := writer.Close(); e != nil {
					t.Error(e)
				} else {
					life.writerClosed = true
				}
			}
		})
		recorder := &restoreRecorder{receiveDispositionRecorder{writer: writer}}
		n.walReadSources, n.walReadSourceLimits = recorder, limits
		n.coreSteps, n.timerSources, n.internalSources, n.inboxSources, n.signerCalls = recorder, recorder, recorder, recorder, recorder
		n.signerSources = &privval.SourceOptions{Namespace: recorder.CaptureRun(), Records: 1024, Bytes: 8 << 20, Observe: func(source privval.Source) {
			writer.Put(journal.Record{Body: &journal.SignerRec{Source: source, Mono: uint64(n.clock.Mono()), WallNs: uint64(n.clock.Now().UnixNano())}})
		}}
		return life, recorder
	}
	closeProcess := func(life *explicitOriginLifetime, recorder *restoreRecorder) {
		life.runner, life.log = n.r, n.log
		if err := life.runner.Close(); err != nil {
			t.Fatal(err)
		}
		life.runnerClosed = true
		// Graceful WAL Close flushes the normal tail before its retained readable
		// observation. Reading before Close would omit ordinary buffered records.
		if err := life.log.Close(); err != nil {
			t.Fatal(err)
		}
		life.logClosed = true
		_, _, source, err := life.log.ReadAllObserved(recorder.CaptureRun(), limits)
		if err != nil {
			t.Fatal(err)
		}
		recorder.ObserveWALRead(journal.WALReadRec{Source: source, Mono: uint64(n.clock.Mono()), WallNs: uint64(n.clock.Now().UnixNano())})
		if err := life.writer.Close(); err != nil {
			t.Fatal(err)
		}
		life.writerClosed = true
	}
	first, firstRecorder := openWriter("normal-origin-before", "/origin-before")
	n.boot()
	proposal := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
	proposal.Header.Time = uint64(n.clock.Now().Unix())
	n.r.Submit(proposal)
	// The same normal scheduling prefix as the existing same-writer regression.
	for i := 0; i < 2; i++ {
		if !n.r.processOne() {
			t.Fatal("normal scheduler input missing", i)
		}
	}
	if n.r.Halted() != nil || len(n.r.internal) == 0 || len(n.net.own(codec.CodePreprepare)) != 1 || len(n.net.own(codec.CodePrepare)) != 1 {
		t.Fatal("normal own vote was not retained", n.r.Halted())
	}
	closeProcess(first, firstRecorder)
	before, err := journal.ReadAll(n.jfs, "/origin-before")
	if err != nil {
		t.Fatal(err)
	}
	var originalOwn []*journal.SignerCallRec
	calls := 0
	for _, row := range before {
		if call, ok := row.Body.(*journal.SignerCallRec); ok {
			if call.Result != "sent" || call.WALWritten != 1 {
				t.Fatal("original signing call incomplete")
			}
			calls++
			originalOwn = append(originalOwn, call)
		}
	}
	if calls != 2 {
		t.Fatal("normal original signing count differs", calls)
	}
	second, secondRecorder := openWriter("normal-origin-after", "/origin-after")
	n.boot() // fresh runner, signer and WAL reader on the same normally closed FS
	if !n.r.replay.Replayed || n.r.replay.Records == 0 {
		t.Fatal("normal reopened process did not restore")
	}
	n.r.Pump()
	closeProcess(second, secondRecorder)
	after, err := journal.ReadAll(n.jfs, "/origin-after")
	if err != nil {
		t.Fatal(err)
	}
	restoredOwn, currentCalls, initialReads := 0, 0, 0
	mapped := make([]int, len(originalOwn))
	for _, row := range after {
		if _, ok := row.Body.(*journal.SignerCallRec); ok {
			currentCalls++
		}
		if read, ok := row.Body.(*journal.WALReadRec); ok && read.Source.Sequence == 1 {
			initialReads++
			if read.Source.Error != "" || read.Source.Unavailable != "" {
				t.Fatal("normal reopened read incomplete")
			}
			for _, frame := range read.Source.Frames {
				if len(frame.Bytes) < 10 || frame.Bytes[8] != 1 || frame.Bytes[9] != 4 {
					continue
				}
				var own ownRec
				if err := rlp.DecodeStrict(frame.Bytes[10:], &own); err != nil || own.Refused != 0 {
					t.Fatal("normal own frame decode differs", err)
				}
				for i, call := range originalOwn {
					if frame.Position.Segment == call.Segment && uint64(frame.Position.Offset) == call.Offset {
						if own.Code != call.RequestCode || !bytes.Equal(own.Payload, call.Payload) {
							t.Fatal("normal original call/code/payload/position differs")
						}
						mapped[i]++
						restoredOwn++
						t.Logf("normal_origin_frame prior_namespace=%q prior_log=%d current_namespace=%q current_log=%d sequence=%d segment=%d offset=%d code=%d payload_sha256=%x", call.WAL.Namespace, call.WAL.Log, read.Source.Namespace, read.Source.Log, read.Source.Sequence, frame.Position.Segment, frame.Position.Offset, own.Code, sha256.Sum256(call.Payload))
					}
				}
			}
		}
	}
	if initialReads != 1 || restoredOwn != 2 {
		t.Fatal("original signed own bytes were not readable at reopen", initialReads, restoredOwn)
	}
	for i, count := range mapped {
		if count != 1 {
			t.Fatal("original call does not map to exactly one reopened frame", i, count)
		}
	}
	bounds := journal.CoreSourceLimits{Records: 4096, Runs: 16, Steps: 4096, Environments: 4096, Outputs: 16384, Bytes: 32 << 20}
	signerBounds := privval.SourceLimits{Lifetimes: 8, Operations: 4096, Records: 4096, Bytes: 32 << 20}
	restore, core, effects, signing, err := journal.CheckRestoredSignerSources(after, bounds, signerBounds)
	if err != nil || restore.Status != "consistent" || core.Status != "consistent" || effects.Status != "consistent" || signing.Status != "unavailable" || signing.Reason != "restored_original_signer_call_missing" {
		t.Fatal("current-only signer evidence boundary differs", restore, core, effects, signing, err)
	}
	priorRestore, priorCore, priorEffects, priorSigning, priorErr := journal.CheckRestoredSignerSources(before, bounds, signerBounds)
	t.Logf("normal_origin_prior restore=%s core=%s effects=%s signer=%s reason=%q calls=%d error=%v", priorRestore.Status, priorCore.Status, priorEffects.Status, priorSigning.Status, priorSigning.Reason, priorSigning.Calls, priorErr)
	t.Logf("normal_cross_writer same_WAL=true original_calls=%d original_signed_own_frames=%d current_calls=%d current_status=%s reason=%s product_repaired=false original_CI_failure_coordinates_identified=false", calls, restoredOwn, currentCalls, signing.Status, signing.Reason)
	originBounds := journal.SignerOriginLimits{Core: journal.CoreSourceLimits{Records: 1 << 20, Runs: 1024, Steps: 1 << 20, Environments: 1 << 20, Outputs: 1 << 22, Bytes: 1 << 30}, Signer: privval.SourceLimits{Lifetimes: 1024, Operations: 1 << 20, Records: 1 << 20, Bytes: 1 << 30}, Writers: 16, Links: 16, Frames: 1 << 20, Bytes: 1 << 30, Work: math.MaxUint64}
	refs := func(previous, current []journal.Record) journal.SignerOriginLink {
		var link journal.SignerOriginLink
		for _, row := range previous {
			if r, ok := row.Body.(*journal.WALReadRec); ok && r.Source.Sequence > link.PreviousRead.Sequence {
				link.PreviousRead = journal.WALReadRef{Namespace: r.Source.Namespace, Log: r.Source.Log, Sequence: r.Source.Sequence}
			}
			if r, ok := row.Body.(*journal.SignerRec); ok && r.Source.Ref.Sequence > link.PreviousSigner.Sequence {
				link.PreviousSigner = r.Source.Ref
			}
		}
		for _, row := range current {
			if r, ok := row.Body.(*journal.RestoreRec); ok && r.Replayed == 1 {
				if link.CurrentRead.Sequence != 0 && link.CurrentRead != r.Read {
					t.Fatal("fixture has multiple actual restore reads")
				}
				link.CurrentRead = r.Read
			}
			if r, ok := row.Body.(*journal.SignerRec); ok && r.Source.Ref.Sequence == 1 {
				link.CurrentSigner = r.Source.Ref
			}
		}
		return link
	}
	origins := &journal.SignerOriginSources{Prior: []journal.SignerOriginRun{{Records: before}}, Links: []journal.SignerOriginLink{refs(before, after)}}
	r, c, e, linked, err := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, origins, originBounds)
	if err != nil || linked.Status != "consistent_on_explicit_origin_witness" || linked.Current.Calls != 0 || linked.InheritedOwnBindings != 2 || !linked.CurrentInspected || !reflect.DeepEqual(linked.Current, signing) || !reflect.DeepEqual(r, restore) || !reflect.DeepEqual(c, core) || !reflect.DeepEqual(e, effects) {
		t.Fatal("explicit two-writer handoff differs", r, c, e, linked, err)
	}
	for _, empty := range []*journal.SignerOriginSources{nil, {}} {
		nr, nc, ne, ns, nerr := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, empty, journal.SignerOriginLimits{})
		if !reflect.DeepEqual(nr, restore) || !reflect.DeepEqual(nc, core) || !reflect.DeepEqual(ne, effects) || !reflect.DeepEqual(ns.Current, signing) || ns.OriginStatus != "not_requested" || fmt.Sprint(nerr) != fmt.Sprint(err) {
			t.Fatal("nil origin changed legacy tuple", ns, nerr)
		}
	}
	// Fresh unsigned refs and limits affect only the read-only inspector.
	wrong := *origins
	wrong.Links = append([]journal.SignerOriginLink(nil), origins.Links...)
	wrong.Links[0].CurrentRead.Sequence += 100
	_, _, _, missing, err := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, &wrong, originBounds)
	if err != nil || missing.Status != "unavailable" {
		t.Fatal("unknown explicit read was inferred", missing, err)
	}
	wrong.Links[0] = origins.Links[0]
	wrong.Links[0].CurrentRead = wrong.Links[0].PreviousRead
	_, _, _, bad, err := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, &wrong, originBounds)
	if err == nil || bad.Status != "inconsistent" {
		t.Fatal("incorrect unsigned edge owner was accepted", bad, err)
	}
	limited := originBounds
	limited.Work = 1
	_, _, _, short, err := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, origins, limited)
	if err != nil || short.Status != "unavailable" || short.CurrentInspected || short.Usage.Work > 1 {
		t.Fatal("budget failure invented current-only inspection", short, err)
	}
	var previousOperations uint64
	for _, row := range before {
		if _, ok := row.Body.(*journal.SignerRec); ok {
			previousOperations++
		}
	}
	priorOutputs, x := journal.CheckCoreStepSources(before, bounds)
	if x != nil || priorOutputs.Status != "consistent" || priorOutputs.Outputs == 0 {
		t.Fatal("normal prior output baseline unavailable", priorOutputs, x)
	}
	currentOutputLimit := originBounds
	currentOutputLimit.Core.Outputs = priorOutputs.Outputs
	currentBoundaryLimit := originBounds
	currentBoundaryLimit.Core.Records = 2 * uint64(len(before))
	currentSignerLimit := originBounds
	currentSignerLimit.Signer.Operations = previousOperations
	for name, limit := range map[string]journal.SignerOriginLimits{"current_boundary_records": currentBoundaryLimit, "current_signer_operations": currentSignerLimit, "current_boundary_outputs": currentOutputLimit} {
		_, _, _, got, x := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, origins, limit)
		if x != nil || got.Status != "unavailable" || got.CurrentInspected || got.Current.Status != "" {
			t.Fatal("mid-inspection origin budget invented legacy result", name, got, x)
		}
	}
	duplicate := &journal.SignerOriginSources{Prior: []journal.SignerOriginRun{{Records: before}, {Records: before}}, Links: []journal.SignerOriginLink{origins.Links[0], origins.Links[0]}}
	_, _, _, duplicateReport, duplicateErr := journal.CheckRestoredSignerSourcesWithOrigins(after, bounds, signerBounds, duplicate, originBounds)
	if !errors.Is(duplicateErr, journal.ErrSignerOrigin) || duplicateReport.Status != "inconsistent" || duplicateReport.CurrentInspected {
		t.Fatal("duplicate unsigned predecessor reference was not rejected before inspection", duplicateReport, duplicateErr)
	}
	third, thirdRecorder := openWriter("normal-origin-third", "/origin-third")
	n.boot()
	n.r.Pump()
	closeProcess(third, thirdRecorder)
	thirdRecords, err := journal.ReadAll(n.jfs, "/origin-third")
	if err != nil {
		t.Fatal(err)
	}
	chain := &journal.SignerOriginSources{Prior: []journal.SignerOriginRun{{Records: before}, {Records: after}}, Links: []journal.SignerOriginLink{refs(before, after), refs(after, thirdRecords)}}
	_, _, _, three, err := journal.CheckRestoredSignerSourcesWithOrigins(thirdRecords, bounds, signerBounds, chain, originBounds)
	if err != nil || three.Status != "consistent_on_explicit_origin_witness" || three.PriorRuns != 2 || three.Links != 2 || three.Current.Calls != 0 || three.InheritedOwnBindings != 2 {
		t.Fatal("three normal lifetimes did not preserve original signing provenance", three, err)
	}
	t.Logf("explicit_origin_witness lifetimes=3 current_calls=%d inherited=%d work=%d physical=%s", three.Current.Calls, three.InheritedOwnBindings, three.Usage.Work, three.PhysicalStatus)

}
