// Command coredet runs the coredet analyzer on the given packages.
//
// Usage (from the root of the wbft module):
//
//	go -C tools build -o ../bin/coredet ./lint/coredet/cmd/coredet
//	bin/coredet ./...
package main

import (
	"github.com/0xmhha/wbft/tools/lint/coredet"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() { singlechecker.Main(coredet.Analyzer) }
