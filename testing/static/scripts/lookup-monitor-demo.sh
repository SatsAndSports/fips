#!/bin/bash
# Trigger a lookup from node A to node C in the A-B-C demo chain and print the
# resulting coord-monitor stream from all three containers.
#
# Usage:
#   ./testing/scripts/build.sh
#   ./testing/static/scripts/generate-configs.sh lookup-monitor-demo
#   docker compose -f testing/static/docker-compose.yml --profile lookup-monitor-demo up -d
#   ./testing/static/scripts/lookup-monitor-demo.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"

ENV_FILE="$STATIC_DIR/generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh lookup-monitor-demo first." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

echo "=== Lookup Monitor Demo (A -> C over A-B-C) ==="
echo "Waiting for peers to connect..."
wait_for_peers fips-node-a 1 30
wait_for_peers fips-node-b 2 30
wait_for_peers fips-node-c 1 30
sleep 2

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo
echo "Triggering discovery lookup from node A to node C..."
docker exec fips-node-a fipsctl lookup "$NPUB_C"
sleep 3

echo
echo "Node A coord-monitor events:"
docker logs --since "$since" fips-node-a 2>&1 | grep full_coord_monitoring || true

echo
echo "Node B coord-monitor events:"
docker logs --since "$since" fips-node-b 2>&1 | grep full_coord_monitoring || true

echo
echo "Node C coord-monitor events:"
docker logs --since "$since" fips-node-c 2>&1 | grep full_coord_monitoring || true
