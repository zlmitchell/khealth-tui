#!/bin/sh
# Build khealth inside a golang container (no local Go needed).
# Usage: ./build.sh [GOOS] [GOARCH]   e.g. ./build.sh linux amd64 | ./build.sh windows amd64
set -e
GOOS=${1:-linux}; GOARCH=${2:-amd64}
EXT=""; [ "$GOOS" = windows ] && EXT=.exe
mkdir -p dist
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W 2>/dev/null || pwd)":/src -w /src \
  -v khealth-gomod:/go/pkg/mod -v khealth-gocache:/root/.cache/go-build \
  -e GOOS="$GOOS" -e GOARCH="$GOARCH" -e CGO_ENABLED=0 golang:1.24 \
  sh -c "go mod tidy && go build -ldflags '-s -w -X k8s-health-tui/internal/config.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)' -o dist/khealth-$GOOS-$GOARCH$EXT ./cmd/khealth"
echo "built dist/khealth-$GOOS-$GOARCH$EXT"
