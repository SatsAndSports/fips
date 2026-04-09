#!/bin/bash
# Gateway integration test: non-FIPS LAN client reaches mesh HTTP server.
#
# Topology:
#   gw-client (non-FIPS) → gw-gateway (fips + fips-gateway) → gw-server (fips + http)
#
# Usage:
#   ./scripts/gateway-test.sh [inject-config]
#
# Subcommands:
#   inject-config  — post-process generated configs to add gateway section
#   (no args)      — run the test (containers must be running)
set -e

trap 'echo ""; echo "Test interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"

GENERATED_DIR="$SCRIPT_DIR/../generated-configs"
ENV_FILE="$GENERATED_DIR/npubs.env"

GATEWAY="fips-gw-gateway"
SERVER="fips-gw-server"
CLIENT="fips-gw-client"

# ── inject-config subcommand ─────────────────────────────────────────────

inject_gateway_config() {
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"

    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found. Run generate-configs.sh gateway first." >&2
        exit 1
    fi

    echo "Injecting gateway config into $config_file"
    python3 -c "
import yaml

with open('$config_file') as f:
    cfg = yaml.safe_load(f)

cfg['gateway'] = {
    'enabled': True,
    'pool': 'fd01::/112',
    'lan_interface': 'eth0',
    'dns': {
        'listen': '[::]:53',
        'ttl': 5,
    },
    'pool_grace_period': 5,
}

with open('$config_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    echo "  ✓ Gateway config injected"
}

if [ "${1:-}" = "inject-config" ]; then
    inject_gateway_config
    exit 0
fi

# ── Main test ────────────────────────────────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh gateway first." >&2
    exit 1
fi

# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

PASSED=0
FAILED=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  $label ... OK"
        PASSED=$((PASSED + 1))
    else
        echo "  $label ... FAIL"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== FIPS Gateway Integration Test ==="
echo ""

# Phase 1: Wait for mesh convergence (gateway ↔ server)
echo "Phase 1: Mesh convergence"
wait_for_peers "$GATEWAY" 1 30 || true
wait_for_peers "$SERVER" 1 30 || true

# Phase 2: Wait for gateway DNS to respond
echo ""
echo "Phase 2: Gateway DNS readiness"
DNS_READY=false
for i in $(seq 1 30); do
    # Try resolving the server's npub via the gateway DNS from the client.
    # Match fd01:: specifically (the pool prefix) to avoid false-positive
    # matches on error messages containing fd02::10.
    local_result=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @fd02::10 2>/dev/null || true)
    if echo "$local_result" | grep -q "^fd01::"; then
        echo "  Gateway DNS responding after ${i}s"
        DNS_READY=true
        break
    fi
    sleep 1
done

if [ "$DNS_READY" != true ]; then
    echo "  WARNING: Gateway DNS did not respond within 30s, continuing anyway"
fi

# Phase 3: Client network setup — route virtual IP pool via gateway
echo ""
echo "Phase 3: Client network setup"
docker exec "$CLIENT" ip -6 route add fd01::/112 via fd02::10 2>/dev/null || true
echo "  Added route fd01::/112 via fd02::10"

# Phase 4: DNS resolution test — resolve server npub from client
echo ""
echo "Phase 4: DNS resolution"
VIRTUAL_IP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @fd02::10 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP" ] && echo "$VIRTUAL_IP" | grep -q "fd01"; then
    check "Resolve ${NPUB_B:0:20}...fips → $VIRTUAL_IP" 0
else
    check "Resolve ${NPUB_B:0:20}...fips (got: '$VIRTUAL_IP')" 1
fi

# Phase 5: End-to-end HTTP test
echo ""
echo "Phase 5: HTTP through gateway"

# Use --resolve to bind the .fips hostname to the virtual IP for curl
if [ -n "$VIRTUAL_IP" ]; then
    RESPONSE=$(docker exec "$CLIENT" curl -6 -s --max-time 10 \
        --resolve "${NPUB_B}.fips:8000:[$VIRTUAL_IP]" \
        "http://${NPUB_B}.fips:8000/" 2>&1) || true

    if echo "$RESPONSE" | grep -q "Fuck IPs"; then
        check "HTTP GET ${NPUB_B:0:20}...fips:8000" 0
    else
        check "HTTP GET (response: '${RESPONSE:0:80}')" 1
    fi
else
    check "HTTP GET (skipped — no virtual IP)" 1
fi

# Phase 6: Verify NAT state on gateway
echo ""
echo "Phase 6: Gateway NAT state"
# Check that nftables rules were created
NFT_RULES=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null || echo "")
if echo "$NFT_RULES" | grep -q "dnat"; then
    check "nftables DNAT rules present" 0
else
    check "nftables DNAT rules" 1
fi

# Phase 7: TTL expiration and pool reclamation
echo ""
echo "Phase 7: TTL expiration and pool reclamation"
# Flush conntrack so stale sessions from Phase 5 don't keep the mapping alive.
docker exec "$GATEWAY" conntrack -F 2>/dev/null || true
# Config uses ttl=5, pool_grace_period=5. Pool tick interval is 10s, so:
#   tick 1 (~10s): TTL expired → Draining (sessions=0 after flush)
#   tick 2 (~20s): grace expired → freed
# Wait 25s to ensure two full tick cycles have passed.
echo "  Waiting 25s for TTL + grace period to expire (two tick cycles)..."
sleep 25

# Query gateway control socket for mapping count
MAPPING_COUNT=$(docker exec "$GATEWAY" bash -c \
    'echo "show_mappings" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
    | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('data',{}).get('mappings',[])))" 2>/dev/null || echo "error")
if [ "$MAPPING_COUNT" = "0" ]; then
    check "Mapping reclaimed after TTL+grace" 0
else
    check "Mapping reclaimed (count: $MAPPING_COUNT)" 1
fi

# Phase 8: SERVFAIL when daemon DNS is down
echo ""
echo "Phase 8: SERVFAIL when daemon DNS is down"
# Kill the fips daemon inside the gateway container (gateway stays running)
docker exec "$GATEWAY" pkill -f "^fips --config" 2>/dev/null || true
sleep 2

# Gateway upstream timeout is 5s, so dig must wait longer than that.
SERVFAIL_RESULT=$(docker exec "$CLIENT" dig +short +tries=1 +time=8 AAAA "test-servfail.fips" @fd02::10 2>&1 || true)
SERVFAIL_STATUS=$(docker exec "$CLIENT" dig +tries=1 +time=8 AAAA "test-servfail.fips" @fd02::10 2>&1 | grep -c "SERVFAIL" || true)
if [ "$SERVFAIL_STATUS" -ge 1 ]; then
    check "SERVFAIL when daemon DNS is down" 0
else
    check "SERVFAIL when daemon DNS down (got: '${SERVFAIL_RESULT:0:80}')" 1
fi

# Phase 9: Cleanup verification (nftables removed on shutdown)
echo ""
echo "Phase 9: Cleanup on shutdown"
# fips-gateway is PID 1 (exec in entrypoint), so SIGTERM stops the container.
# Verify cleanup by checking container logs for the shutdown sequence.
docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
sleep 1

LOGS=$(docker logs --tail=20 "$GATEWAY" 2>&1)
if echo "$LOGS" | grep -q "shutdown complete"; then
    check "Gateway shutdown completed cleanly" 0
else
    check "Gateway shutdown (no completion message in logs)" 1
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
