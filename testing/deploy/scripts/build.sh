#!/bin/bash
# Build the FIPS binaries, generate configs, and build Docker images.
#
# Usage: ./build.sh [mesh-name]
#   mesh-name: optional; derives unique node identities via sha256(mesh-name|node-id)
#              default: "podman-test"
#
# The resulting containers are run with:
#   docker compose -f testing/deploy/docker-compose.yml up -d
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MESH_NAME="${1:-podman-test}"
TOPOLOGY="podman-mesh"

# Find project root (directory containing Cargo.toml)
PROJECT_ROOT="$(cd "$DEPLOY_DIR/../.." && pwd)"
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "Error: Cannot find Cargo.toml at $PROJECT_ROOT" >&2
    echo "Expected layout: <project-root>/testing/deploy/scripts/build.sh" >&2
    exit 1
fi

echo "=== FIPS Deploy Build ==="
echo "  Mesh name:  $MESH_NAME"
echo "  Topology:   $TOPOLOGY"
echo ""

# ── Step 1: Compile FIPS ────────────────────────────────────────────
UNAME_S=$(uname -s)
CARGO_TARGET="x86_64-unknown-linux-musl"

# Ensure musl target is installed (static linking — no glibc dependency)
if ! rustup target list --installed | grep -q "$CARGO_TARGET"; then
    echo "Installing Rust target $CARGO_TARGET..."
    rustup target add "$CARGO_TARGET"
fi

if [ "$UNAME_S" = "Darwin" ]; then
    echo "Detected macOS host — cross-compiling for Linux..."
    if ! command -v cargo-zigbuild &>/dev/null; then
        echo "Error: cargo-zigbuild not found." >&2
        echo "Install it: cargo install cargo-zigbuild" >&2
        exit 1
    fi

    echo "Building FIPS (release, musl, cross-compile)..."
    cargo zigbuild --release --target "$CARGO_TARGET" \
        --manifest-path="$PROJECT_ROOT/Cargo.toml"
else
    echo "Building FIPS (release, musl)..."
    # Use system gcc for C dependencies (secp256k1-sys) when musl-gcc
    # is not installed. The Rust linker handles musl linking regardless.
    CC="${CC:-gcc}" cargo build --release --target "$CARGO_TARGET" \
        --manifest-path="$PROJECT_ROOT/Cargo.toml"
fi

BINARY_DIR="$PROJECT_ROOT/target/$CARGO_TARGET/release"

echo "Copying binaries to build context..."
cp "$BINARY_DIR/fips"    "$DEPLOY_DIR/fips"
cp "$BINARY_DIR/fipsctl" "$DEPLOY_DIR/fipsctl"
cp "$BINARY_DIR/fipstop" "$DEPLOY_DIR/fipstop"
echo ""

# ── Step 2: Generate node configs ──────────────────────────────────
echo "Generating node configurations..."
"$SCRIPT_DIR/generate-configs.sh" "$TOPOLOGY" "$MESH_NAME"
echo ""

# Print generated npubs for reference (needed if registering with external peers)
NPUB_ENV="$DEPLOY_DIR/generated-configs/npubs.env"
if [ -f "$NPUB_ENV" ]; then
    echo "=== Node identities ==="
    grep "^NPUB_" "$NPUB_ENV" | while IFS= read -r line; do
        echo "  $line"
    done
    echo ""
    echo "  Note: share NPUB_A with the external VPS operator so it can"
    echo "  accept inbound connections from your gateway node."
    echo ""
fi

# ── Step 3: Build container images ─────────────────────────────────
echo "Building Docker images..."
docker compose -f "$DEPLOY_DIR/docker-compose.yml" build
echo ""

echo "=== Done ==="
echo ""
echo "Start the mesh:"
echo "  docker compose -f $DEPLOY_DIR/docker-compose.yml up -d"
echo ""
echo "Check status:"
echo "  docker exec fips-node-a fipsctl show peers"
echo "  docker exec fips-node-a fipsctl show links"
echo "  docker exec fips-node-a fipsctl show tree"
echo ""
echo "Test connectivity:"
echo "  docker exec fips-node-b ping6 -c3 node-c.fips"
echo ""
echo "Monitor (TUI):"
echo "  docker exec -it fips-node-a fipstop"
echo ""
echo "Stop:"
echo "  docker compose -f $DEPLOY_DIR/docker-compose.yml down"
