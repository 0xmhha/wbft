package coredet_test

import (
	"testing"

	"github.com/0xmhha/wbft/tools/lint/coredet"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestCoredet(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), coredet.Analyzer,
		"github.com/0xmhha/wbft/consensus",
		"github.com/0xmhha/wbft/consensus/runner",
		"github.com/0xmhha/wbft/header",
		"github.com/0xmhha/wbft/types",
		"github.com/0xmhha/wbft/node",
	)
}
