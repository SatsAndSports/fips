#!/bin/bash
# Entrypoint for directory-mode test container.
# Starts Tor, optionally waits for hostname file, then starts FIPS.

set -e

echo "Starting dnsmasq..."
dnsmasq

# Check if this node uses directory mode (match the YAML value, not comments)
IS_DIRECTORY_MODE=false
if grep -qE '^\s+mode:\s+"directory"' /etc/fips/fips.yaml 2>/dev/null; then
    IS_DIRECTORY_MODE=true
fi

# Pre-create HiddenServiceDir with correct permissions.
# Tor requires 0700 on the directory.
HIDDEN_SERVICE_DIR="/var/lib/tor/fips_onion_service"
if [ "$IS_DIRECTORY_MODE" = true ]; then
    mkdir -p "$HIDDEN_SERVICE_DIR"
    chmod 700 "$HIDDEN_SERVICE_DIR"
fi

echo "Starting Tor daemon..."
tor -f /etc/tor/torrc &

# If this node uses directory mode, wait for Tor to create the hostname file
if [ "$IS_DIRECTORY_MODE" = true ]; then
    HOSTNAME_FILE="${HIDDEN_SERVICE_DIR}/hostname"
    echo "Waiting for Tor to create ${HOSTNAME_FILE}..."
    for i in $(seq 1 120); do
        if [ -f "$HOSTNAME_FILE" ]; then
            echo "Tor hostname file ready after ${i}s: $(cat "$HOSTNAME_FILE")"
            break
        fi
        sleep 1
    done

    if [ ! -f "$HOSTNAME_FILE" ]; then
        echo "FATAL: Tor did not create hostname file within 120s"
        exit 1
    fi
fi

echo "Starting FIPS daemon..."
exec fips --config /etc/fips/fips.yaml
