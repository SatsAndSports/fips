#!/bin/bash
# Export full_coord_monitoring logs from running containers into host-side
# artifacts, then derive JSONL and Graphviz DOT files.
#
# Usage:
#   ./testing/static/scripts/export-coord-monitor.sh <label> [container ...]
#
# Examples:
#   ./testing/static/scripts/export-coord-monitor.sh lookup-monitor-demo \
#       fips-node-a fips-node-b fips-node-c
#
# If no containers are provided, defaults to the three-node lookup demo.

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
run_id="${timestamp}_${safe_label}"
run_dir="$REPO_ROOT/artifacts/coord-monitor/$run_id"

mkdir -p "$run_dir"

python3 "$REPO_ROOT/testing/lib/coord_monitor.py" \
    --run-dir "$run_dir" \
    --run-id "$run_id" \
    --topology "$LABEL" \
    --from-docker "$@"

echo
echo "Graphviz DOT outputs:"
echo "  $run_dir/graph/coord-only.dot"
echo "  $run_dir/graph/message-only.dot"
echo "  $run_dir/graph/combined.dot"
echo
echo "If Graphviz is installed, render with:"
echo "  dot -Tsvg '$run_dir/graph/combined.dot' -o '$run_dir/graph/combined.svg'"
