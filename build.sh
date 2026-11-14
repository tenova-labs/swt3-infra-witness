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

# Step 2: Build static binaries (verify it compiles before Docker)
echo "[2/5] Building static binary (amd64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o swt3-infra-witness ./cmd/swt3-infra-witness/
ls -lh swt3-infra-witness

echo "[3/5] Building static binary (arm64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o swt3-infra-witness-arm64 ./cmd/swt3-infra-witness/
ls -lh swt3-infra-witness-arm64
echo ""

# Step 4: Build container image
echo "[4/5] Building container image..."
docker build --no-cache \
  -t "${IMAGE}:${TAG}" \
  -t "${IMAGE}:latest" \
  .

SIZE=$(docker image inspect "${IMAGE}:${TAG}" --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1048576}')
echo ""
echo "Built: ${IMAGE}:${TAG} ($SIZE)"

# Step 5: Push (if requested)
if [ "$PUSH" = true ]; then
  echo ""
  echo "[5/5] Pushing to ghcr.io..."
  docker push "${IMAGE}:${TAG}"
  docker push "${IMAGE}:latest"
  echo ""
  echo "Published:"
  echo "  ${IMAGE}:${TAG}"
  echo "  ${IMAGE}:latest"
else
  echo ""
  echo "[5/5] Skipped push (use --push to publish)"
  echo ""
  echo "To push manually:"
  echo "  docker push ${IMAGE}:${TAG}"
  echo "  docker push ${IMAGE}:latest"
fi

# Compute SHA-256 of both binaries for release notes and Terraform modules
SHA_AMD64=$(sha256sum swt3-infra-witness | awk '{print $1}')
SHA_ARM64=$(sha256sum swt3-infra-witness-arm64 | awk '{print $1}')
echo ""
echo "Binary SHA-256 (amd64): $SHA_AMD64"
echo "Binary SHA-256 (arm64): $SHA_ARM64"
echo "Docker pull:            docker pull ${IMAGE}:${TAG}"
echo "Run:                    docker run -e SWT3_API_KEY=axm_live_xxx ${IMAGE}:${TAG} --mode server"

# Write checksums file for Terraform module validation (red team #1)
cat > checksums.json <<EOF
{
  "version": "${TAG}",
  "binaries": {
    "linux_amd64": {
      "filename": "swt3-infra-witness",
      "sha256": "${SHA_AMD64}"
    },
    "linux_arm64": {
      "filename": "swt3-infra-witness-arm64",
      "sha256": "${SHA_ARM64}"
    }
  }
}
EOF
echo ""
echo "Checksums written to checksums.json"

# Clean up local binaries (container has its own copy)
rm -f swt3-infra-witness swt3-infra-witness-arm64
