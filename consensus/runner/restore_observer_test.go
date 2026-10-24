package runner

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

type restoreRecorder struct{ receiveDispositionRecorder }

func (o *restoreRecorder) ObserveWALRead(r journal.WALReadRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *restoreRecorder) ObserveSignerCall(r journal.SignerCallRec) {
	o.writer.Put(journal.Record{Body: &r})
}
func (o *restoreRecorder) ObserveRestore(r journal.RestoreRec) {
	o.writer.Put(journal.Record{Body: &r})
}

func TestRestoreSourcesNormalGracefulRestartToFirstLiveStep(t *testing.T) {
	k := newKeys(t, 4)
	var original []journal.Record
	var originalWAL []wal.Record
	var originalSent []sent
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, k, 0)
		n.noJournal = true
		n.chain.head.Time = uint64(n.clock.Now().Unix()) - 1
		config := []byte(`{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":1099511627776,"proposerPolicy":0}}}`)
		writer, err := journal.Open(journal.Options{FS: n.jfs, Dir: "/restore-source", Synchronous: true}, journal.Identity{Run: "normal-restore", Core: journal.CoreOptions{ChainConfig: config, Self: n.opts.Self, Improvements: uint64(n.opts.Improvements), BacklogLimit: uint64(n.opts.BacklogLimit), TimerTrace: journal.TimerTraceVersion}})
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			o := &restoreRecorder{receiveDispositionRecorder{writer: writer}}
			n.walReadSources = o
			n.walReadSourceLimits = wal.ReadSourceLimits{Frames: 1024, Bytes: 8 << 20}
			n.coreSteps = o
			n.timerSources = o
			n.internalSources = o
			n.signerCalls = o
			n.signerSources = &privval.SourceOptions{Namespace: o.CaptureRun(), Records: 1024, Bytes: 8 << 20, Observe: func(source privval.Source) {
				writer.Put(journal.Record{Body: &journal.SignerRec{Source: source, Mono: uint64(n.clock.Mono()), WallNs: uint64(n.clock.Now().UnixNano())}})
			}}
		}
		n.boot()
		b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
		b.Header.Time = uint64(n.clock.Now().Unix())
		n.r.Submit(b)
		// Normal scheduler iterations handle the actual builder request and own proposal.
		// Graceful shutdown may occur with the resulting own vote still queued.
		for i := 0; i < 2; i++ {
			if !n.r.processOne() {
				t.Fatal("normal scheduler input missing", i)
			}
		}
		if n.r.Halted() != nil || len(n.r.internal) == 0 || len(n.net.own(codec.CodePreprepare)) != 1 || len(n.net.own(codec.CodePrepare)) != 1 {
			t.Fatal("normal proposal did not retain its own queued vote", n.r.Halted())
		}
		if err := n.r.Stop(); err != nil {
			t.Fatal(err)
		}
		if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
		if !n.r.replay.Replayed || len(n.r.internal) == 0 || n.r.d.Journal != nil {
			t.Fatal("normal restore lost its live own-vote input", n.r.replay)
		}
		n.r.Pump()
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		fs, dir := n.log.FS()
		records, _, err := wal.ReadAll(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			originalWAL = records
			originalSent = slices.Clone(n.net.sent)
			continue
		}
		if !reflect.DeepEqual(originalWAL, records) || !reflect.DeepEqual(originalSent, n.net.sent) {
			t.Fatal("restore observation changed WAL or signed sends")
		}
		original, err = journal.ReadAll(n.jfs, "/restore-source")
		if err != nil {
			t.Fatal(err)
		}
	}
	// Both actors and every log have closed. All following negatives change
	// detached diagnostic metadata only, never a packet, signer or live input.
	limits := journal.CoreSourceLimits{Records: 4096, Runs: 16, Steps: 4096, Environments: 4096, Outputs: 16384, Bytes: 32 << 20}
	signerLimits := privval.SourceLimits{Lifetimes: 8, Operations: 4096, Records: 4096, Bytes: 32 << 20}
	restore, core, effects, signing, err := journal.CheckRestoredSignerSources(original, limits, signerLimits)
	if signing.Status != "consistent" || signing.Calls != 2 || signing.WALOwnBindings != 2 || signing.Signer.Signed != 2 {
		t.Fatal("actual core/signing/WAL joins not reconstructed", signing, err)
	}
	if effects.Status != "consistent" || effects.Arms == 0 || effects.InternalAppends == 0 || effects.FirstLiveDispatches != 1 {
		t.Fatal("restore effects not bound", effects, err)
	}
	if err != nil || restore.Status != "consistent" || core.Status != "consistent" || restore.Reads != 2 || restore.Runs != 2 || restore.Attempts != 1 || restore.Inputs == 0 {
		t.Fatal("normal restore and first live step not reconstructed", restore, core, err)
	}
	legacy, err := journal.CheckCoreStepSources(original, limits)
	if err != nil || legacy.Status != "unavailable" || legacy.Reason != "restored_prefix_not_reconstructed" {
		t.Fatal("default checker guard relaxed", legacy, err)
	}
	if restore.SignerStatus != "consistent_on_initial_witness" || restore.ApplicationStatus != "unavailable" || restore.PhysicalStatus != "unavailable" {
		t.Fatal("read reconstruction claimed unrelated proof", restore)
	}
	var target, firstLive int
	for i, rec := range original {
		if r, ok := rec.Body.(*journal.RestoreRec); ok && r.Replayed == 1 {
			target = i
		}
		if r, ok := rec.Body.(*journal.CoreStepRec); ok && r.ReplayedPrefix && firstLive == 0 {
			firstLive = i
		}
	}
	if target == 0 || firstLive <= target {
		t.Fatal("actual restore/live order missing", target, firstLive)
	}
	for _, mode := range []string{"boundary", "input", "read", "engine", "snapshot", "attempt_missing", "attempt_duplicate", "generation", "own", "timer", "after_live", "missing", "live_step", "live_marker", "installed_generation", "installed_own", "missing_all_restored_live", "cold_snapshot", "cold_height", "cold_generations", "cold_own", "restore_arm_missing", "restore_arm_owner", "restore_deadline", "restore_append_missing", "restore_append_owner", "restore_pop_missing", "restore_dispatch_missing", "signer_initial_missing", "signer_call_missing", "signer_ref", "signer_request", "signer_signature", "signer_write", "signer_state", "signer_owner", "own_position", "own_log", "own_write_result", "signer_after_call", "zero_budget"} {
		t.Run(mode, func(t *testing.T) {
			copied := slices.Clone(original)
			var r journal.RestoreRec
			raw, err := rlp.Encode(original[target].Body.(*journal.RestoreRec))
			if err != nil {
				t.Fatal(err)
			}
			if err = rlp.DecodeStrict(raw, &r); err != nil {
				t.Fatal(err)
			}
			copied[target].Body = &r
			l := limits
			switch mode {
			case "boundary":
				r.Boundary++
			case "input":
				r.Inputs[0]++
			case "read":
				r.Read.Sequence++
			case "engine":
				r.EngineRun++
			case "snapshot":
				r.Snapshot[0] ^= 1
			case "attempt_missing":
				r.Attempts = nil
			case "attempt_duplicate":
				r.Attempts = append(r.Attempts, r.Attempts[0])
			case "installed_generation":
				r.Generations[0]++
			case "installed_own":
				r.Own[0].Payload[0] ^= 1
			case "generation":
				r.Attempts[0].Generations[0]++
			case "own":
				if len(r.Attempts[0].Own) == 0 {
					t.Fatal("normal own evidence missing")
				}
				r.Attempts[0].Own[0].Payload[0] ^= 1
			case "timer":
				if len(r.Attempts[0].Timers[0]) == 0 {
					t.Fatal("normal timer evidence missing")
				}
				r.Attempts[0].Timers[0][0] ^= 1
			case "after_live":
				copied[target], copied[firstLive] = copied[firstLive], copied[target]
			case "missing":
				copied = append(copied[:target], copied[target+1:]...)
			case "live_step", "live_marker":
				s := *copied[firstLive].Body.(*journal.CoreStepRec)
				if mode == "live_step" {
					s.Step++
				} else {
					s.ReplayedPrefix = false
				}
				copied[firstLive].Body = &s
			case "missing_all_restored_live":
				filtered := make([]journal.Record, 0, len(copied))
				for _, rec := range copied {
					if c, ok := rec.Body.(*journal.CoreStepRec); ok && c.ReplayedPrefix {
						continue
					}
					filtered = append(filtered, rec)
				}
				copied = filtered
			case "cold_snapshot", "cold_height", "cold_generations", "cold_own":
				for i, rec := range copied {
					if cold, ok := rec.Body.(*journal.RestoreRec); ok && cold.Replayed == 0 {
						c := *cold
						switch mode {
						case "cold_generations":
							c.Generations = slices.Clone(c.Generations)
							c.Generations[0]++
						case "cold_own":
							c.Own = []journal.RestoreOwn{{Code: uint64(codec.CodePrepare), Payload: []byte{0xc0}}}
						case "cold_snapshot":
							c.Snapshot[0] ^= 1
						default:
							c.From = "11"
						}
						copied[i].Body = &c
						break
					}
				}
			case "restore_arm_missing", "restore_arm_owner", "restore_deadline":
				for i, rec := range copied {
					if timer, ok := rec.Body.(*journal.TimerRec); ok && timer.Source == "restore" && timer.Action == "arm" {
						if mode == "restore_arm_missing" {
							copied = append(copied[:i], copied[i+1:]...)
						} else {
							c := *timer
							if mode == "restore_arm_owner" {
								c.ArmEngineRun++
							} else {
								c.Deadline++
							}
							copied[i].Body = &c
						}
						break
					}
				}
			case "restore_append_missing", "restore_append_owner", "restore_pop_missing", "restore_dispatch_missing":
				for i, rec := range copied {
					if internal, ok := rec.Body.(*journal.InternalRec); ok && internal.EngineRun == 2 && ((internal.Origin == "replay" && (mode == "restore_append_missing" || mode == "restore_append_owner")) || internal.Action == "pop" && mode == "restore_pop_missing" || internal.Action == "dispatch" && mode == "restore_dispatch_missing") {
						if mode == "restore_append_owner" {
							c := *internal
							c.EngineRun++
							copied[i].Body = &c
						} else {
							copied = append(copied[:i], copied[i+1:]...)
						}
						break
					}
				}
			case "signer_initial_missing":
				for i, rec := range copied {
					if signer, ok := rec.Body.(*journal.SignerRec); ok && signer.Source.Action == "initial" {
						copied = append(copied[:i], copied[i+1:]...)
						break
					}
				}
			case "signer_call_missing", "signer_ref", "signer_request", "signer_signature", "own_position", "own_log", "own_write_result", "signer_write", "signer_state", "signer_owner", "signer_after_call":
				index := -1
				for i, rec := range copied {
					if _, ok := rec.Body.(*journal.SignerCallRec); ok {
						index = i
						break
					}
				}
				if index < 0 {
					t.Fatal("actual signer call missing")
				}
				var call journal.SignerCallRec
				raw, e := rlp.Encode(copied[index].Body.(*journal.SignerCallRec))
				if e != nil {
					t.Fatal(e)
				}
				if e = rlp.DecodeStrict(raw, &call); e != nil {
					t.Fatal(e)
				}
				copied[index].Body = &call
				switch mode {
				case "signer_call_missing":
					copied = append(copied[:index], copied[index+1:]...)
				case "signer_ref":
					call.Source.Sequence++
				case "signer_request":
					call.Request[0] ^= 1
				case "signer_signature":
					call.Signature[0] ^= 1
				case "own_position":
					call.Offset++
				case "own_log":
					call.WAL.Log++
				case "own_write_result":
					call.WALWritten = 0
				default:
					for i, rec := range copied {
						if signer, ok := rec.Body.(*journal.SignerRec); ok && signer.Source.Ref == call.Source {
							var c journal.SignerRec
							raw, e := rlp.Encode(signer)
							if e != nil {
								t.Fatal(e)
							}
							if e = rlp.DecodeStrict(raw, &c); e != nil {
								t.Fatal(e)
							}
							switch mode {
							case "signer_write":
								c.Source.Write[0] ^= 1
							case "signer_state":
								c.Source.After[0] ^= 1
							case "signer_owner":
								c.Source.Ref.Namespace = "another-owner"
							case "signer_after_call":
								copied[i], copied[index] = copied[index], copied[i]
							}
							if mode != "signer_after_call" {
								copied[i].Body = &c
							}
							break
						}
					}
				}
			case "zero_budget":
				l.Bytes = 0
			}
			a, b, f, g, e := journal.CheckRestoredSignerSources(copied, l, signerLimits)
			if e == nil && a.Status == "consistent" && b.Status == "consistent" && f.Status == "consistent" && g.Status == "consistent" {
				t.Fatal("copied contradictory restore accepted", mode, a, b)
			}
		})
	}
}
