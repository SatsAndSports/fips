#!/bin/bash
# Push FIPS node stats to a topology collector.
#
# Usage:
#   ./push.sh [collector_address]
#
# Examples:
#   ./push.sh                            # default: collector.fips
#   ./push.sh collector.fips
#   ./push.sh npub1meshz5gqcvzkrjnvce7wty8zdwq9lyag5u9yqfvh0uzg4qca0g5s0h7wmt.fips

COLLECTOR="${1:-npub1meshz5gqcvzkrjnvce7wty8zdwq9lyag5u9yqfvh0uzg4qca0g5s0h7wmt.fips}"

STATUS=$(fipsctl show status 2>/dev/null)
TREE=$(fipsctl show tree 2>/dev/null)
PEERS=$(fipsctl show peers 2>/dev/null)

if [ -z "$STATUS" ] || [ -z "$TREE" ] || [ -z "$PEERS" ]; then
    echo "Error: fipsctl not available or FIPS not running" >&2
    exit 1
fi

curl -6 -g -X POST "http://$COLLECTOR:8080/report" \
    -H "Content-Type: application/json" \
    -d "{\"status\": $STATUS, \"tree\": $TREE, \"peers\": $PEERS}"
echo
