package heightlow_test

import (
	"slices"
	"testing"

	"github.com/0xmhha/wbft/tools/lint/heightlow"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestHeightlow(t *testing.T) {
	res := analysistest.Run(t, analysistest.TestData(), heightlow.Analyzer,
		"github.com/0xmhha/wbft/types",
		"github.com/0xmhha/wbft/chain/header",
	)
	for _, r := range res {
		if r.Pass.Pkg.Path() != "github.com/0xmhha/wbft/chain/header" {
			continue
		}
		if got := r.Result.(heightlow.Rows); !slices.Equal(got, heightlow.Rows{"HH-20", "HH-21", "HH-74"}) {
			t.Errorf("rows %v", got)
		}
	}
}
