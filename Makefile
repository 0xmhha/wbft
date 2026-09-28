# Developer shortcuts; CI runs the same commands (.github/workflows).
export CGO_ENABLED := 1

.PHONY: all build test lint coredet heightlow deps lint-negative tools adapter tracegen

all: build test lint

build:
	go build ./...
	go -C tools build ./...

test:
	go vet ./...
	go test ./...
	go -C tools vet ./...
	go -C tools test ./...

lint: coredet heightlow deps
	golangci-lint run ./...
	cd tools && golangci-lint run ./...

bin/coredet: $(wildcard tools/lint/coredet/*.go tools/lint/coredet/cmd/coredet/*.go)
	go -C tools build -o ../bin/coredet ./lint/coredet/cmd/coredet

coredet: bin/coredet
	bin/coredet ./...

bin/heightlow: $(wildcard tools/lint/heightlow/*.go tools/lint/heightlow/cmd/heightlow/*.go)
	go -C tools build -o ../bin/heightlow ./lint/heightlow/cmd/heightlow

# The rows of the height-handling table that the implemented milestones must
# annotate at least once (scripts/heightlow-rows.txt).
heightlow: bin/heightlow
	bin/heightlow -require "$$(tr -d ' ' < scripts/heightlow-rows.txt | paste -sd, -)" ./...

deps:
	scripts/check-deps.sh

lint-negative:
	scripts/lint-negative.sh

adapter:
	go build -o bin/wbft-vector-adapter ./cmd/wbft-vector-adapter

tracegen:
	go -C tools build -o ../bin/tracegen ./tracegen
