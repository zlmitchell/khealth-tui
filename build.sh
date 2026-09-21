#!/bin/sh
# Build khealth for one target or all of them, with a sha256 checksums file.
#
#   ./build.sh                 -> dist/khealth-linux-amd64
#   ./build.sh windows amd64   -> dist/khealth-windows-amd64.exe
#   ./build.sh all             -> every target below + dist/checksums.txt
#
# Environment:
#   BUILD_LOCAL=1   use the Go toolchain on PATH (CI) instead of the golang container
#   VERSION=v1.2.3  version embedded in the binary (default: git describe, or "dev")
#   GO_IMAGE        container image used when BUILD_LOCAL is not set
#   DIST=dir        output directory (default dist)
set -e

# renovate: datasource=docker depName=golang
GO_IMAGE=${GO_IMAGE:-golang:1.26}
TARGETS="linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
LDFLAGS="-s -w -X k8s-health-tui/internal/config.Version=$VERSION"

DIST=${DIST:-dist}
mkdir -p "$DIST"

build_one() {
  goos=$1; goarch=$2
  ext=""; [ "$goos" = windows ] && ext=.exe
  out="$DIST/khealth-$goos-$goarch$ext"
  if [ -n "$BUILD_LOCAL" ]; then
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/khealth
  else
    MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W 2>/dev/null || pwd)":/src -w /src \
      -v khealth-gomod:/go/pkg/mod -v khealth-gocache:/root/.cache/go-build \
      -e GOOS="$goos" -e GOARCH="$goarch" -e CGO_ENABLED=0 "$GO_IMAGE" \
      sh -c "go mod tidy && go build -trimpath -ldflags '$LDFLAGS' -o '$out' ./cmd/khealth"
  fi
  BUILT="$BUILT ${out#$DIST/}"
  echo "built $out ($VERSION)"
}

checksums() {
  # only the files this run produced, so stray builds in dist/ stay out of the list
  cd "$DIST"
  rm -f checksums.txt
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum $BUILT > checksums.txt
  else
    shasum -a 256 $BUILT > checksums.txt
  fi
  echo "wrote $DIST/checksums.txt"
  cat checksums.txt
}

BUILT=""
if [ "${1:-}" = all ]; then
  for t in $TARGETS; do
    build_one "${t%/*}" "${t#*/}"
  done
  checksums
else
  build_one "${1:-linux}" "${2:-amd64}"
fi
