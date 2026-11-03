#!/bin/bash
# Publish-day checklist for swt3-infra-witness.
# Run this before publishing a new release.
#
# Usage:
#   ./publish.sh           # dry run (verify everything, don't push)
#   ./publish.sh --ship    # verify + push container + create GitHub release

set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

SHIP=false
[ "${1:-}" = "--ship" ] && SHIP=true

GREEN="\033[32m"
RED="\033[31m"
DIM="\033[90m"
RESET="\033[0m"

passed=0
failed=0

pass() { echo -e "  ${GREEN}PASS${RESET}  $1"; ((passed++)); }
fail() { echo -e "  ${RED}FAIL${RESET}  $1"; ((failed++)); }

echo ""
echo "=== swt3-infra-witness publish checklist ==="
echo ""

# 1. Go tests
echo "-- Step 1: Go tests --"
if go test ./... -count=1 > /dev/null 2>&1; then
  pass "All Go tests pass"
else
  fail "Go tests failed"
fi

# 2. Cross-language parity
echo "-- Step 2: Cross-language parity --"
if go test ./internal/canonical/ -run TestCanonicalizeKeyOrder -count=1 > /dev/null 2>&1; then
  pass "Go canonical JSON test"
else
  fail "Go canonical JSON test"
fi

NODE_HASH=$(node -e '
const crypto = require("crypto");
const fields = {actor:"arn:aws:iam::123456789012:role/deploy-agent",operation:"RunInstances",region:"us-east-1",resource:"arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",status:"Success",time:"2026-10-31T14:22:07Z"};
const sorted = {};
for (const key of Object.keys(fields).sort()) sorted[key] = fields[key];
console.log(crypto.createHash("sha256").update(JSON.stringify(sorted)).digest("hex"));
' 2>/dev/null || echo "FAILED")

if [ "$NODE_HASH" = "052b1b32ca03c99cb51d7e558906dbaf20c2a9dfccf39ca37d2448bb14e88c80" ]; then
  pass "Node canonical hash = Go ${DIM}(052b1b32...)${RESET}"
else
  fail "Node canonical hash mismatch: $NODE_HASH"
fi

# 3. Build binary
echo "-- Step 3: Build binary --"
if CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o swt3-infra-witness ./cmd/swt3-infra-witness/ 2>/dev/null; then
  SHA=$(sha256sum swt3-infra-witness | awk '{print $1}')
  pass "Static binary built ${DIM}(SHA: ${SHA:0:16}...)${RESET}"
else
  fail "Binary build failed"
  SHA="UNKNOWN"
fi

# 4. Dry-run all formats
echo "-- Step 4: Dry-run all formats --"
export SWT3_API_KEY=publish-check

for fmt in cloudtrail azure gcp ocsf; do
  if ./swt3-infra-witness --dry-run --format "$fmt" --input "sample-events/${fmt/cloudtrail/cloudtrail}-sample.json" > /dev/null 2>&1; then
    pass "$fmt dry-run"
  else
    # Try with correct filename mapping
    sample="sample-events/"
    case $fmt in
      cloudtrail) sample+="cloudtrail-sample.json" ;;
      azure) sample+="azure-activity-sample.json" ;;
      gcp) sample+="gcp-audit-sample.json" ;;
      ocsf) sample+="ocsf-sample.json" ;;
    esac
    if ./swt3-infra-witness --dry-run --format "$fmt" --input "$sample" > /dev/null 2>&1; then
      pass "$fmt dry-run"
    else
      fail "$fmt dry-run"
    fi
  fi
done

if ./swt3-infra-witness --dry-run --input sample-events/cloudtrail-sample.json > /dev/null 2>&1; then
  pass "Auto-detect dry-run"
else
  fail "Auto-detect dry-run"
fi

# 5. Security scrub
echo "-- Step 5: Security scrub --"
LEAKED=$(grep -r '108\.61\|axiom-admin\|localhost:5678\|supabase\.co\|STRIPE_SECRET\|\.env\.local' . --include='*.go' --include='*.json' --include='*.md' 2>/dev/null | grep -v '.git' | wc -l)
if [ "$LEAKED" = "0" ]; then
  pass "No leaked internals"
else
  fail "Found $LEAKED leaked internal references"
fi

# 6. Container build
echo "-- Step 6: Container image --"
DOCKER_CMD="docker"
# Use sudo if docker socket requires it
if ! docker info > /dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi
if command -v docker > /dev/null 2>&1; then
  if $DOCKER_CMD build -t ghcr.io/tenova-labs/swt3-infra-witness:0.1.0 . > /dev/null 2>&1; then
    SIZE=$($DOCKER_CMD image inspect ghcr.io/tenova-labs/swt3-infra-witness:0.1.0 --format '{{.Size}}' 2>/dev/null | awk '{printf "%.1f MB", $1/1048576}')
    pass "Container image builds ${DIM}($SIZE)${RESET}"
  else
    fail "Container image build failed"
  fi
else
  echo -e "  ${DIM}SKIP${RESET}  Docker not available"
fi

# Cleanup
rm -f swt3-infra-witness

# Summary
echo ""
echo "=== Results: $passed passed, $failed failed ==="
echo ""

if [ "$failed" -gt 0 ]; then
  echo -e "${RED}BLOCKED: Fix failures before publishing.${RESET}"
  exit 1
fi

if [ "$SHIP" = true ]; then
  echo "Shipping..."
  echo ""
  ./build.sh 0.1.0 --push
  echo ""
  echo -e "${GREEN}Published. Update GitHub release notes with SHA-256: $SHA${RESET}"
else
  echo "All checks passed. Ready to ship."
  echo "Run ./publish.sh --ship to publish."
fi
