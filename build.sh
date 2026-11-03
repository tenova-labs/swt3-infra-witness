#!/bin/bash
# Build and optionally push the swt3-infra-witness container image.
#
# Usage:
#   ./build.sh              # build only (ghcr.io/tenova-labs/swt3-infra-witness:0.1.0)
#   ./build.sh 0.2.0        # build with custom tag
#   ./build.sh --push       # build + push to ghcr.io
#   ./build.sh 0.2.0 --push # custom tag + push
#
# Prerequisites:
#   - Docker (or Podman)
#   - For --push: docker login ghcr.io (GITHUB_TOKEN with write:packages)
#
# The image is ~7MB (distroless base + static Go binary).

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Parse args
TAG="0.1.0"
PUSH=false
for arg in "$@"; do
  case "$arg" in
    --push) PUSH=true ;;
    *) TAG="$arg" ;;
  esac
done

IMAGE="ghcr.io/tenova-labs/swt3-infra-witness"

echo "=== swt3-infra-witness build ==="
echo ""

# Step 1: Run Go tests
echo "[1/4] Running tests..."
go test ./... -count=1
echo ""

# Step 2: Build static binary (verify it compiles before Docker)
echo "[2/4] Building static binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o swt3-infra-witness ./cmd/swt3-infra-witness/
ls -lh swt3-infra-witness
echo ""

# Step 3: Build container image
echo "[3/4] Building container image..."
docker build --no-cache \
  -t "${IMAGE}:${TAG}" \
  -t "${IMAGE}:latest" \
  .

SIZE=$(docker image inspect "${IMAGE}:${TAG}" --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1048576}')
echo ""
echo "Built: ${IMAGE}:${TAG} ($SIZE)"

# Step 4: Push (if requested)
if [ "$PUSH" = true ]; then
  echo ""
  echo "[4/4] Pushing to ghcr.io..."
  docker push "${IMAGE}:${TAG}"
  docker push "${IMAGE}:latest"
  echo ""
  echo "Published:"
  echo "  ${IMAGE}:${TAG}"
  echo "  ${IMAGE}:latest"
else
  echo ""
  echo "[4/4] Skipped push (use --push to publish)"
  echo ""
  echo "To push manually:"
  echo "  docker push ${IMAGE}:${TAG}"
  echo "  docker push ${IMAGE}:latest"
fi

# Compute SHA-256 of the binary for release notes
SHA=$(sha256sum swt3-infra-witness | awk '{print $1}')
echo ""
echo "Binary SHA-256: $SHA"
echo "Docker pull:    docker pull ${IMAGE}:${TAG}"
echo "Run:            docker run -e SWT3_API_KEY=axm_live_xxx ${IMAGE}:${TAG} --mode server"

# Clean up local binary (container has its own copy)
rm -f swt3-infra-witness
