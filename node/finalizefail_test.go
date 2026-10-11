package node

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/0xmhha/wbft/app"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// finalizeErrApp is an application whose FinalizeBlock returns err.
type finalizeErrApp struct {
	app.Application
	err error
}

func (a finalizeErrApp) FinalizeBlock(context.Context, app.FinalizeRequest) (app.FinalizeResponse, error) {
	return app.FinalizeResponse{}, a.err
}

// TestFinalizeImportFailure: an *app.ImportError from FinalizeBlock is
// reported as an import failure of the decided block on the sealed_locally
// path, recorded as bad when it wraps ErrInvalidBlock. Other errors and
// success report nothing; the error goes back to the runner unchanged.
func TestFinalizeImportFailure(t *testing.T) {
	b := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(7)}}
	invalid := &app.ImportError{Step: "H17", Class: "invalid", Err: fmt.Errorf("%w: seals", app.ErrInvalidBlock)}
	other := &app.ImportError{Step: "P4", Class: "unavailable", Err: errors.New("state pruned")}
	for _, c := range []struct {
		name    string
		err     error
		reports bool
		bad     bool
	}{
		{"invalid block", fmt.Errorf("finalize: %w", invalid), true, true},
		{"import error not invalid", other, true, false},
		{"conflicting block", app.ErrConflictingBlock, false, false},
		{"success", nil, false, false},
	} {
		var got []app.ImportFailure
		d := &appDriver{a: finalizeErrApp{err: c.err}, ctx: context.Background(), failed: func(f app.ImportFailure) { got = append(got, f) }}
		if err := d.FinalizeBlock(b, types.Round{}); !errors.Is(err, c.err) && err != c.err {
			t.Fatalf("%s: error %v, want %v", c.name, err, c.err)
		}
		if (len(got) == 1) != c.reports || len(got) > 1 {
			t.Fatalf("%s: reports %+v", c.name, got)
		}
		if !c.reports {
			continue
		}
		f := got[0]
		if f.Path != app.SealedLocally || f.RecordedBad != c.bad || f.Number.Cmp(b.Header.Number) != 0 || f.Hash != codec.BlockHash(b.Header) || f.Err == nil {
			t.Fatalf("%s: failure %+v", c.name, f)
		}
	}
}
