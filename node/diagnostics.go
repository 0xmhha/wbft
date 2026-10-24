package node

import (
	"fmt"

	"github.com/0xmhha/wbft/consensus/privval"
	"github.com/0xmhha/wbft/consensus/runner"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
)

// DiagnosticWriter belongs to the caller. Its run must be unique for each
// actual Node start, and its Put must retain detached values and return promptly.
// The caller supplies the conditional journal identity and closes the writer
// only after Node.Stop. Node never installs it as a functional replay journal.
type DiagnosticWriter interface {
	journal.Writer
	CaptureRun() string
}

// DiagnosticOptions enable source observations for the explicit cache policy.
// Bounds limit additional evidence copies, not the runtime's original WAL read,
// signing work, application execution, writer retention or process resources.
// Nil preserves the original Node behavior.
type DiagnosticOptions struct {
	Writer                     DiagnosticWriter
	WALRead                    wal.ReadSourceLimits
	SignerRecords, SignerBytes uint64
	ApplicationBytes           uint64
	// WALReadOnStop explicitly requests one diagnostic read after the original
	// WAL Close. It adds shutdown I/O and original ReadAll allocations; WALRead
	// bounds only the detached evidence copy, not that I/O or allocation.
	WALReadOnStop bool
}

func freezeDiagnostics(cfg Config, d *Deps) error {
	if d.Diagnostics == nil {
		return nil
	}
	o := *d.Diagnostics
	if cfg.CachePolicy == nil || !cfg.Journal.Disabled {
		return fmt.Errorf("%w: diagnostics require the explicit cache policy and a disabled functional journal", ErrConfig)
	}
	if o.Writer == nil || cfg.RunID == "" || o.Writer.CaptureRun() != cfg.RunID {
		return fmt.Errorf("%w: diagnostics require an explicit matching writer run", ErrConfig)
	}
	if o.WALRead.Frames == 0 || o.WALRead.Bytes == 0 || o.SignerRecords == 0 || o.SignerBytes == 0 || o.ApplicationBytes == 0 {
		return fmt.Errorf("%w: diagnostic copy limits must be positive", ErrConfig)
	}
	if _, ok := d.Transport.(transport.Observed); !ok {
		return fmt.Errorf("%w: diagnostic transport observations are unavailable", ErrConfig)
	}
	d.Diagnostics = &o
	return nil
}

func (f *sessionFrameRecorder) ObserveTimerSource(s journal.TimerRec) {
	if s.Sequence == 0 || s.EngineRun == 0 || len(s.Input) == 0 && s.Action != "clear" && s.Action != "cancel" {
		f.jw.Put(journal.Record{Body: &journal.GapRec{Dropped: 1, ByKind: []journal.KindCount{{Kind: uint64(journal.KindTimer), Count: 1}}, FirstMono: s.Mono, LastMono: s.Mono}})
		return
	}
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveAppQueueSource(s journal.AppQueueRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveFinalizeSource(s journal.FinalizeRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveInboxSource(s journal.InboxRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveInternalSource(s journal.InternalRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveInputSelection(s journal.SelectionRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveReceiveDispatch(s journal.ReceiveDispatchRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveWALRead(s journal.WALReadRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveRestore(s journal.RestoreRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) ObserveSignerCall(s journal.SignerCallRec) {
	f.jw.Put(journal.Record{Body: &s})
}
func (f *sessionFrameRecorder) observeSigner(s privval.Source) {
	f.jw.Put(journal.Record{Body: &journal.SignerRec{Source: s, Mono: uint64(f.clock.Mono()), WallNs: uint64(f.clock.Now().UnixNano())}})
}

func (f *sessionFrameRecorder) connect(d *runner.Deps, limits wal.ReadSourceLimits) {
	d.CoreSteps, d.TimerSources, d.AppQueueSources, d.FinalizeSources = f, f, f, f
	d.InboxSources, d.InternalSources, d.SelectionSources, d.ReceiveDispatchSources = f, f, f, f
	d.WALReadSources, d.WALReadSourceLimits, d.SignerCalls = f, limits, f
}
