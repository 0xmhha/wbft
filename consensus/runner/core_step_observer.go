package runner

import (
	"bytes"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/p2p/transport"
	"github.com/0xmhha/wbft/types"
)

// CoreEnvObservation keeps an actual environment answer, including ordered
// validator-key nil presence that the older Env RLP alone cannot distinguish.
// Bytes are newly encoded; no application or validator-set pointer escapes.
type CoreEnvObservation struct {
	Bytes               []byte
	ValidatorKeyPresent []bool
}

// CoreStepObservation is a detached diagnostic value for one actual live Step.
// It does not activate the functional journal, replay a cache or authenticate
// the recording writer/configuration. A replayed prefix is marked explicitly;
// restored WAL steps are never fabricated as new live observations.
type CoreStepObservation struct {
	EngineRun, Step         uint64
	ReplayedPrefix          bool
	Via, InputKind          string
	Input, Outputs          []byte
	OutDigest               types.Hash
	Environment             []CoreEnvObservation
	Origin                  transport.ReceiveOrigin
	StreamRun               string
	Stream                  uint64
	Before, After           transport.ValidationContext
	BeforeKnown, AfterKnown bool
	Entry, Observed         CoreStepMoment
	Unavailable             string
}

type CoreStepMoment struct {
	Mono   int64
	WallNs int64
}

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
	o.Before, o.BeforeKnown = receiveContextMetadata(before)
	o.After, o.AfterKnown = receiveContextMetadata(after)
	o.Origin = sc.q.origin
	stream := sc.q.stream
	if sc.q.deferred != nil {
		d := sc.q.deferred.record
		o.Origin = transport.ReceiveOrigin{WriterRun: d.CaptureRun, CaptureID: d.Capture}
		stream = d.stream
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
