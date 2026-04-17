#!/bin/bash
# Start a live coord-monitor collector that persists events across container
# restarts/recreations for a named set of Docker containers.
#
# Usage:
#   ./testing/static/scripts/collect-coord-monitor-live.sh <label> [container ...]
#
# Examples:
#   ./testing/static/scripts/collect-coord-monitor-live.sh lookup-monitor-demo \
#       fips-node-a fips-node-b fips-node-c

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

LABEL="${1:-lookup-monitor-demo}"
if [ $# -gt 0 ]; then
    shift
fi

if [ $# -eq 0 ]; then
    set -- fips-node-a fips-node-b fips-node-c
fi

timestamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
safe_label="$(printf '%s' "$LABEL" | tr ' /' '__')"
run_id="${timestamp}_${safe_label}_live"
run_dir="$REPO_ROOT/artifacts/coord-monitor/live/$run_id"

mkdir -p "$run_dir"

echo "Starting live coord-monitor collector"
echo "  run_dir: $run_dir"
echo "  containers: $*"
echo
echo "Stop with Ctrl-C. After stopping, derive DOT graphs with:"
echo "  python3 testing/lib/coord_monitor.py --run-dir '$run_dir/post' --run-id '${run_id}_post' --topology '$LABEL' --from-raw '$run_dir'/raw/*.log"
echo

python3 "$REPO_ROOT/testing/lib/coord_monitor_live.py" \
    --run-dir "$run_dir" \
    --run-id "$run_id" \
    --containers "$@"
