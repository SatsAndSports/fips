#!/bin/bash
# Start a live coord-monitor collector that persists events across container
# restarts/recreations for a named set of Docker containers.
#
# Usage:
#   ./testing/static/scripts/collect-coord-monitor-live.sh <session-name> [container ...]
#
# Examples:
#   ./testing/static/scripts/collect-coord-monitor-live.sh my-session \
#       fips-node-a fips-node-b fips-node-c

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

SESSION_NAME="${1:-lookup-monitor-demo}"
if [ $# -gt 0 ]; then
    shift
fi

if [ $# -eq 0 ]; then
    set -- fips-node-a fips-node-b fips-node-c
fi

safe_session="$(printf '%s' "$SESSION_NAME" | tr ' /' '__')"
run_dir="$REPO_ROOT/artifacts/coord-monitor/live/$safe_session"

mkdir -p "$run_dir"

echo "Starting live coord-monitor collector"
echo "  session_name: $SESSION_NAME"
echo "  run_dir: $run_dir"
echo "  containers: $*"
echo
echo "Stop with Ctrl-C. After stopping, derive DOT graphs with:"
echo "  make ${safe_session}.svg"
echo

python3 "$REPO_ROOT/testing/lib/coord_monitor_live.py" \
    --run-dir "$run_dir" \
    --session-name "$SESSION_NAME" \
    --containers "$@"
