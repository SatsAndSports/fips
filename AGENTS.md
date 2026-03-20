# FIPS Deploy — Multi-Node Mesh with Topology Collector

Most deployment assets described here live under `testing/deploy/`.
This document also references the Nostr transport implementation in
`src/transport/nostr/` and transport config definitions in
`src/config/transport.rs`.

## Overview

This repo includes a Docker-based FIPS deployment with:

- a 5-node local UDP mesh,
- a topology collector that stores raw reports in SQLite,
- an external VPS peer reached through `node-a`, and
- a 2-node Nostr test path where one node bridges into the UDP mesh.

Collected reports can be rendered as a Graphviz topology diagram.

## Architecture

```
               VPS (217.77.8.91, external)
                |
              node-a (gateway, depth 1)
                |          \
    root85g6 (root, depth 0, ground node_addr for tree root election)
             / | \          \
        node-b node-c collector (vanity npub: npub1mesh...)
                              \
                         node-nostr-a (UDP + Nostr bridge)
                              |
                        ~~~relay~~~
                              |
                         node-nostr-b (Nostr-only)
```

- 5 local containers on the Docker bridge network `172.20.0.0/24` use UDP transport
- `node-nostr-a` peers with `node-a` over UDP and with `node-nostr-b` over Nostr
- `node-nostr-b` is Nostr-only and reaches the main mesh through `node-nostr-a`
- `node-a` is the gateway to the external VPS peer
- `root85g6` wins root election via a ground `node_addr` (`000016d3...`)
- the collector uses a ground, vanity `npub1mesh...` identity with a hand-written config
- the checked-in Nostr configs are static and currently match the default mesh name `podman-test`

If you run `testing/deploy/scripts/build.sh` with a different mesh name,
regenerated UDP configs will change identities, but
`testing/deploy/configs/nostr/` will not. Update those files too if you
want the Nostr demo topology to remain consistent.

## Quick Start

```bash
# Build binaries, generate configs, build Docker images
# Use the default mesh name unless you also update testing/deploy/configs/nostr/
testing/deploy/scripts/build.sh

# Start the mesh
docker compose -f testing/deploy/docker-compose.yml up -d

# Verify peers are connected
docker exec fips-node-a fipsctl show peers
```

## Directory Structure

### Container setup

- `testing/deploy/Dockerfile` — Debian slim image with FIPS binaries, dnsmasq, curl, python3
- `testing/deploy/docker-compose.yml` — 7 services with TUN and `NET_ADMIN`
- `testing/deploy/.dockerignore` — limits the build context to the FIPS binaries
- `testing/deploy/resolv.conf` — routes DNS through dnsmasq -> FIPS DNS responder

### Topology and config generation

- `testing/deploy/configs/topologies/podman-mesh.yaml` — UDP mesh topology plus the `nostr_a` bridge node
- `testing/deploy/configs/node.template.yaml` — shared YAML template (symlink into `testing/static/`)
- `testing/deploy/configs/nostr/` — hand-written configs for the Nostr bridge node and Nostr-only node
- `testing/deploy/scripts/generate-configs.sh` — shared config generator (symlink into `testing/static/`)
- `testing/deploy/scripts/derive-keys.py` — shared key derivation helper (symlink into `testing/static/`)
- `testing/deploy/scripts/build.sh` — compiles musl binaries, regenerates configs, builds Docker images

### Collector service

- `testing/deploy/collector/server.py` — HTTP server that stores raw report bodies in SQLite
- `testing/deploy/collector/push.sh` — client script that gathers `fipsctl` output and POSTs it back
- `testing/deploy/collector/entrypoint.sh` — collector container entrypoint
- `testing/deploy/collector/visualize.py` — merges reports and emits DOT or SVG topology output

### Nostr transport source

- `src/transport/nostr/mod.rs` — `NostrTransport`, relay tasks, reconnect logic, stats, tests
- `src/transport/nostr/event.rs` — NIP-01 event building/signing and relay message parsing
- `src/config/transport.rs` — `NostrConfig` and transport config integration

### Key tools

- `tools/keytool/` — standalone Rust tool for derivation and grinding
  - `cargo run -- show` — derive and display keys for current mesh nodes
  - `cargo run -- grind-root` — grind node names for the smallest `node_addr`
  - `cargo run -- grind-vanity [prefix]` — grind random keypairs for a vanity `npub` prefix

### Generated / local artifacts

- `testing/deploy/generated-configs/` — regenerated FIPS YAML configs
- `testing/deploy/data/` — collector SQLite database and rendered diagrams
- `testing/deploy/fips`, `testing/deploy/fipsctl`, `testing/deploy/fipstop` — copied build outputs
- `tools/keytool/target/` — Rust build artifacts

## Collector

The collector is a FIPS node that also runs an HTTP service on port 80.
Any node that can route to the collector can submit a report.

### Endpoints

- `GET /` — serves `push.sh` for `curl | bash` usage
- `POST /report` — stores the request body verbatim in SQLite
- `GET /reports` — returns recent report metadata only (`id`, `received_at`)
- `GET /health` — liveness check

There is currently no schema validation, deduplication, or authentication
layer in the collector; it stores raw POST bodies as-is.

### Pushing a report

The simplest mesh-native report submission flow is:

```bash
curl -6 -s http://npub1meshz5gqcvzkrjnvce7wty8zdwq9lyag5u9yqfvh0uzg4qca0g5s0h7wmt.fips | bash
```

That fetches `push.sh` from the collector over FIPS, gathers
`fipsctl show status/tree/peers`, and POSTs the combined JSON back to
the collector.

From inside a container:

```bash
docker exec fips-node-a bash -c \
  "curl -6 -s http://npub1meshz5gqcvzkrjnvce7wty8zdwq9lyag5u9yqfvh0uzg4qca0g5s0h7wmt.fips | bash"
```

### Generating a topology diagram

`visualize.py` always generates DOT. If Graphviz `dot` is available, it
renders SVG; `--dot` forces DOT output.

```bash
python3 testing/deploy/collector/visualize.py testing/deploy/data/collector.db > mesh.svg
python3 testing/deploy/collector/visualize.py testing/deploy/data/collector.db --dot > mesh.dot
```

The diagram currently shows:

- black solid arrows — current spanning-tree edges
- orange solid arrows — historical tree edges that are no longer current
- gray dashed lines — non-tree links
- bold node border — current root
- dotted node border — nodes that never submitted a report
- edge labels — RTT and transport type when known

Node labels include display name, truncated `npub`, truncated `node_addr`,
and tree depth.

## Nostr Transport

FIPS supports a Nostr relay transport that wraps FIPS packets in
ephemeral Nostr events (`kind=21210`) and exchanges them through one or
more WebSocket relays.

### How it works

- packet payloads are Base64-encoded into the event `content`
- recipients are addressed via `p` tags containing raw hex x-only pubkeys
- the node's FIPS identity keypair is reused to sign outgoing events
- each configured relay runs in its own async task
- outbound events are broadcast to all configured relays
- relay tasks reconnect with exponential backoff
- per-transport stats track publishes, receives, bytes, relay connects/disconnects, and decode errors

Current implementation note: inbound relay messages are minimally parsed
and routed; the transport relies on relay subscription filtering and the
higher FIPS layer for trust/authentication, rather than enforcing full
local Nostr event verification.

### Config format

Single instance:

```yaml
transports:
  nostr:
    relays:
      - "ws://relay.example.com:7777"
    # kind: 21210
    # mtu: 1280
```

Like other transports, named Nostr instances are also supported.

Peer addressing:

```yaml
peers:
  - npub: "npub1..."
    alias: "my-peer"
    addresses:
      - transport: nostr
        addr: "abcdef0123456789...64_char_hex_pubkey..."
    connect_policy: auto_connect
```

The `addr` field is the peer's hex-encoded x-only public key, i.e. the
raw form behind the peer's `npub`.

### Running the tests

```bash
# Unit tests only
cargo test --lib transport::nostr

# Unit + relay integration tests (requires ws://127.0.0.1:7777)
cargo test --lib transport::nostr -- --include-ignored
```

The ignored tests are:

- `test_send_recv_via_relay`
- `test_bidirectional_via_relay`

They require a reachable local relay at `ws://127.0.0.1:7777`.

## Docker Nostr nodes

Two Nostr-enabled nodes are included in the deployment:

- `node-nostr-a` (`172.20.0.20`) — UDP + Nostr bridge node
- `node-nostr-b` (`172.20.0.21`) — Nostr-only node that reaches the mesh through `node-nostr-a`

Their checked-in configs live in `testing/deploy/configs/nostr/` and
are mounted directly by Compose. Those files should be kept in git.

The checked-in configs currently point at `ws://80.78.18.182:7777`.
If that relay changes or a different environment is used, update the
`relays:` field in those files.

`nostr_a` also appears in `testing/deploy/configs/topologies/podman-mesh.yaml`
so the generator adds it as a UDP peer in `node-a`'s generated config.

```bash
# Start just the Nostr nodes
docker compose -f testing/deploy/docker-compose.yml up -d node-nostr-a node-nostr-b

# Check the bridge node: it should see node-a (udp) and node-nostr-b (nostr)
docker exec fips-node-nostr-a fipsctl show peers

# Pure Nostr path
docker exec fips-node-nostr-a ping6 -c3 node-nostr-b.fips

# Cross-transport path into the UDP mesh
docker exec fips-node-nostr-b ping6 -c3 node-a.fips

# Logs
docker logs fips-node-nostr-a
docker logs fips-node-nostr-b
```

## Useful Commands

```bash
# Core state
docker exec fips-node-a fipsctl show peers
docker exec fips-node-a fipsctl show tree
docker exec fips-node-a fipsctl show links
docker exec fips-node-a fipsctl show status

# Mesh pings
docker exec fips-node-b ping6 -c3 node-a.fips
docker exec fips-node-b ping6 -c3 vps.fips

# Nostr tests
docker exec fips-node-nostr-a ping6 -c3 node-nostr-b.fips
docker exec fips-node-nostr-b ping6 -c3 node-a.fips

# TUI
docker exec -it fips-node-a fipstop

# Bandwidth test
docker exec -d fips-node-a iperf3 -s
docker exec fips-node-b iperf3 -6 -c node-a.fips -t 5

# Push reports from all current containers, then regenerate the diagram
for node in \
  fips-node-root \
  fips-node-a \
  fips-node-b \
  fips-node-c \
  fips-node-collector \
  fips-node-nostr-a \
  fips-node-nostr-b
do
  docker exec "$node" bash -c \
    "curl -6 -s http://npub1meshz5gqcvzkrjnvce7wty8zdwq9lyag5u9yqfvh0uzg4qca0g5s0h7wmt.fips | bash"
done
python3 testing/deploy/collector/visualize.py testing/deploy/data/collector.db > mesh.svg

# Stop / start the mesh
docker compose -f testing/deploy/docker-compose.yml down
docker compose -f testing/deploy/docker-compose.yml up -d
```
