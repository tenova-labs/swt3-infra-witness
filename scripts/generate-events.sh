#!/bin/sh
# generate-events.sh -- POST sample events to the infra-witness server.
#
# Reads all sample event files and sends them one at a time with a delay.
# Used by docker-compose.dev.yml to demonstrate the witness pipeline.
#
# Usage:
#   WITNESS_URL=http://infra-witness:8080 ./scripts/generate-events.sh

set -e

WITNESS_URL="${WITNESS_URL:-http://infra-witness:8080}"
EVENTS_DIR="${EVENTS_DIR:-/events}"
DELAY="${DELAY:-3}"

echo ""
echo "  SWT3 Event Generator"
echo "  Target: ${WITNESS_URL}"
echo "  Events: ${EVENTS_DIR}"
echo "  Delay:  ${DELAY}s between files"
echo ""

# Wait for witness server to be ready
echo "  Waiting for witness server..."
TRIES=0
while [ $TRIES -lt 30 ]; do
  if wget -q -O /dev/null "${WITNESS_URL}/healthz" 2>/dev/null; then
    echo "  Witness server ready."
    break
  fi
  TRIES=$((TRIES + 1))
  sleep 1
done

if [ $TRIES -ge 30 ]; then
  echo "  ERROR: Witness server not ready after 30s" >&2
  exit 1
fi

echo ""

# Send each sample file
ROUND=1
while true; do
  echo "  --- Round ${ROUND} ---"
  for f in "${EVENTS_DIR}"/*.json; do
    [ -f "$f" ] || continue
    BASENAME=$(basename "$f")
    echo "  Sending ${BASENAME}..."

    RESPONSE=$(wget -q -O - \
      --header="Content-Type: application/json" \
      --post-file="$f" \
      "${WITNESS_URL}/" 2>&1) || true

    if echo "$RESPONSE" | grep -q '"ok":true'; then
      COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
      echo "    -> ${COUNT:-?} events witnessed"
    else
      echo "    -> response: ${RESPONSE}" >&2
    fi

    sleep "${DELAY}"
  done
  ROUND=$((ROUND + 1))
  echo ""
  echo "  Pausing 10s before next round..."
  sleep 10
done
