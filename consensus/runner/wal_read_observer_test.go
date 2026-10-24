package runner

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/wal"
	"github.com/0xmhha/wbft/observe/journal"
)

type walReadObservations struct{ records []journal.WALReadRec }

func (*walReadObservations) CaptureRun() string                    { return "normal-restore-reader" }
func (o *walReadObservations) ObserveWALRead(r journal.WALReadRec) { o.records = append(o.records, r) }

func TestWALReadSourcesPreserveNormalOwnSigningAndGracefulRestore(t *testing.T) {
	k := newKeys(t, 4)
	var reference []wal.Record
	var referenceSent []sent
	for _, enabled := range []bool{false, true} {
		n := newTNode(t, k, 0)
		n.noJournal = true
		n.chain.head.Time = uint64(n.clock.Now().Unix()) - 1
		observed := new(walReadObservations)
		if enabled {
			n.walReadSources = observed
			n.walReadSourceLimits = wal.ReadSourceLimits{Frames: 1024, Bytes: 8 << 20}
		}
		n.boot()
		b := block(t, 10, 1, k.addrs[0], codec.BlockHash(n.chain.head))
		b.Header.Time = uint64(n.clock.Now().Unix())
		n.r.Submit(b)
		n.r.Pump()
		if n.r.Halted() != nil || len(n.net.own(codec.CodePreprepare)) != 1 || len(n.net.own(codec.CodePrepare)) != 1 {
			t.Fatal("normal own proposal or signing failed", n.r.Halted())
		}
		if err := n.r.Stop(); err != nil {
			t.Fatal(err)
		}
		if err := n.r.Start(context.Background(), n.chain.head.Number.AddUint64(1)); err != nil {
			t.Fatal(err)
		}
		if !n.r.replay.Replayed || n.r.replay.Records == 0 || n.r.d.Journal != nil {
			t.Fatal("normal prefix was not restored or diagnostics enabled functional journaling", n.r.replay)
		}
		n.r.Pump()
		if err := n.r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := n.log.Close(); err != nil {
			t.Fatal(err)
		}
		fs, dir := n.log.FS()
		records, _, err := wal.ReadAll(fs, dir)
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			reference = records
			referenceSent = append([]sent(nil), n.net.sent...)
			continue
		}
		if !reflect.DeepEqual(reference, records) || !reflect.DeepEqual(referenceSent, n.net.sent) {
			t.Fatal("read observation changed original WAL or signed network outputs")
		}
		if len(observed.records) != 2 {
			t.Fatal("expected one original read per normal start", len(observed.records))
		}
		first, restored := observed.records[0].Source, observed.records[1].Source
		if first.Unavailable != "" || restored.Unavailable != "" || first.Namespace != "normal-restore-reader" || restored.Namespace != first.Namespace || first.Log != restored.Log || first.Sequence != 1 || restored.Sequence != 2 || len(first.Frames) != 0 || len(restored.Frames) == 0 {
			t.Fatal("original readable prefix or read owner lost", first, restored)
		}
		// Every actor and log is closed before a copied diagnostic value is changed.
		saved := bytes.Clone(restored.Frames[0].Bytes)
		observed.records[1].Source.Frames[0].Bytes[0] ^= 1
		unchanged, _, err := wal.ReadAll(fs, dir)
		if err != nil || !reflect.DeepEqual(records, unchanged) || bytes.Equal(saved, observed.records[1].Source.Frames[0].Bytes) {
			t.Fatal("detached metadata changed original WAL", err)
		}
	}
}
