MODULE := github.com/catnapstudio/serverdog-agent
export PATH := $(shell go env GOPATH)/bin:$(PATH)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILT_AT ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuiltAt=$(BUILT_AT)

.PHONY: generate lint test vmtest pebbletest dist darwin clean

generate:
	buf generate

lint:
	buf lint
	go vet ./...

test:
	go test ./...

vmtest:
	scripts/vm-test.sh ubuntu-24.04
	scripts/vm-test.sh ubuntu-26.04

pebbletest:
	scripts/pebble-test.sh

# -buildvcs=false: the same tag gives the same binary whether it is built in a clone or from an archive of the
# source, so a build can be compared with what runs on a server.
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/serverdog-agent-linux-amd64 ./cmd/serverdog-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/serverdog-agent-linux-arm64 ./cmd/serverdog-agent
	cd dist && shasum -a 256 serverdog-agent-linux-amd64 serverdog-agent-linux-arm64 > SHA256SUMS

darwin:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/serverdog-agent-darwin-arm64 ./cmd/serverdog-agent

clean:
	rm -rf dist
