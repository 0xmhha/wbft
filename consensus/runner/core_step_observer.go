package runner

import (
	"bytes"
	"github.com/0xmhha/wbft/codec"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// Source values use the separate durable diagnostic schema, never StepRec.
type CoreEnvObservation = journal.CoreEnvObservation
type CoreStepObservation = journal.CoreStepRec
type CoreStepMoment = journal.CoreStepMoment

// CoreStepObserver must return promptly. It runs on the consensus loop after
// execution and may retain/alter its detached value without changing the core,
// WAL or functional journal. A nil observer avoids serialization and hashing.
type CoreStepObserver interface{ ObserveCoreStep(CoreStepObservation) }

func observeCoreEnvironment(call inputlog.EnvCall) (CoreEnvObservation, error) {
	encoded, err := inputlog.EncodeEnv(call)
	if err != nil {
		return CoreEnvObservation{}, err
	}
	env := CoreEnvObservation{Bytes: encoded}
	if call.Kind == inputlog.EnvValidatorsAt && call.Validators != nil {
		env.ValidatorKeyPresent = make([]bool, call.Validators.Len())
		for i := range env.ValidatorKeyPresent {
			env.ValidatorKeyPresent[i] = call.Validators.At(i).BLSPublicKey != nil
		}
	}
	return env, nil
}

func coreStepMoment(stamp event.Stamp) CoreStepMoment {
	return CoreStepMoment{Mono: int64(stamp.Mono), WallNs: stamp.Wall.UnixNano()}
}

func (r *Runner) observeCoreStep(sc *stepCtx, kind string, body []byte, before, after *consensus.Snapshot) {
	observer := r.d.CoreSteps
	if observer == nil {
		return
	}
	o := CoreStepObservation{EngineRun: r.engineRun, Step: sc.step, ReplayedPrefix: r.replay.Replayed, Via: sc.q.via, InputKind: kind, Input: bytes.Clone(body), Entry: coreStepMoment(r.stepAt)}
	o.CoreSelf, o.Improvements, o.BacklogLimit = r.cfg.Core.Self, uint64(r.cfg.Core.Improvements), int64(r.cfg.Core.BacklogLimit)
	if r.env != nil && r.env.head != nil {
		var err error
		o.Head, err = codec.EncodeHeader(r.env.head)
		if err != nil {
			o.Unavailable = "head_encoding"
		}
	}
	o.Before, o.BeforeKnown = receiveContextMetadata(before)
	o.After, o.AfterKnown = receiveContextMetadata(after)
	o.Origin = sc.q.origin
	stream := sc.q.stream
	if sc.q.deferred != nil {
		d := sc.q.deferred.record
		o.Origin = transport.ReceiveOrigin{WriterRun: d.CaptureRun, CaptureID: d.Capture}
		stream = d.stream
	}
	// A partially observed capture number cannot claim a writer namespace.
	if o.Origin.WriterRun == "" || o.Origin.CaptureID == 0 {
		o.Origin = transport.ReceiveOrigin{}
	}
	o.StreamRun, o.Stream = stream.ObservationRun(), stream.ObservationID()
	var err error
	o.Outputs, err = inputlog.EncodeOutputs(sc.outs)
	if err != nil {
		o.Unavailable = "output_encoding"
	} else {
		o.OutDigest, err = inputlog.OutDigest(sc.outs)
		if err != nil {
			o.Unavailable = "output_digest"
		}
	}
	for _, answer := range sc.env {
		env, err := observeCoreEnvironment(answer.call)
		if err != nil {
			o.Unavailable = "environment_encoding"
			continue
		}
		o.Environment = append(o.Environment, env)
	}
	o.Observed = CoreStepMoment{Mono: int64(r.d.Clock.Mono()), WallNs: r.d.Clock.Now().UnixNano()}
	observer.ObserveCoreStep(o)
}
