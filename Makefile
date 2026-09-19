VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -s -w -X k8s-health-tui/internal/config.Version=$(VERSION)

.PHONY: build test vet fmt docker-build

build:
	go build -ldflags "$(LDFLAGS)" -o khealth ./cmd/khealth

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

docker-build:
	./build.sh linux amd64
	./build.sh windows amd64
