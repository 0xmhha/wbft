# Developer shortcuts; CI runs the same commands (.github/workflows).
export CGO_ENABLED := 1

.PHONY: all build test lint coredet deps lint-negative tools adapter tracegen

all: build test lint

build:
	go build ./...
	go -C tools build ./...

test:
	go vet ./...
	go test ./...
	go -C tools vet ./...
	go -C tools test ./...

lint: coredet deps
	golangci-lint run ./...
	cd tools && golangci-lint run ./...

bin/coredet: $(wildcard tools/lint/coredet/*.go tools/lint/coredet/cmd/coredet/*.go)
	go -C tools build -o ../bin/coredet ./lint/coredet/cmd/coredet

coredet: bin/coredet
	bin/coredet ./...

deps:
	scripts/check-deps.sh

lint-negative:
	scripts/lint-negative.sh

adapter:
	go build -o bin/wbft-vector-adapter ./cmd/wbft-vector-adapter

tracegen:
	go -C tools build -o ../bin/tracegen ./tracegen
