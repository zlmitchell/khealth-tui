VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -s -w -X github.com/zlmitchell/khealth-tui/internal/config.Version=$(VERSION)

.PHONY: build test vet fmt tidy-check dist docker-build

build:
	go build -ldflags "$(LDFLAGS)" -o khealth ./cmd/khealth

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# what CI runs: the module files must not change after tidy
tidy-check:
	go mod tidy
	git diff --exit-code go.mod go.sum

# every release target + dist/checksums.txt, with the Go on PATH
dist:
	BUILD_LOCAL=1 ./build.sh all

docker-build:
	./build.sh all
