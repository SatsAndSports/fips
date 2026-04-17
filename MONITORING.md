# Monitoring

## Purpose

This repo includes a dedicated coord-monitoring stream for observing how FIPS
nodes advertise, forward, and learn coordinate information.

The monitoring stream is intended to support:
- graphing child-parent relationships learned from coordinate paths
- graphing lookup message flow between peers
- later experiments involving dishonest nodes, fake roots, and large bloom
  filters

## Event Stream

The monitoring target is:

```text
full_coord_monitoring
```

The event schema is:

```text
coord_monitor_v2
```

Each event is logged as one JSON payload line and includes:
- `observed_at_ms`
- `event`
- canonical node identifiers as raw `node_addr`
- optional `identities` enrichment with `npub` and `display_name`
- optional ordered `coords` arrays

## Canonical Identity

Graphs and derived data use raw `node_addr` as the canonical node key.

`npub` is enrichment only.

This matters because:
- some nodes may know an `npub` for an address while others do not
- later-learned `npub`s can still annotate earlier-observed `node_addr`s

The post-processing step merges all observed `identities` maps into a single
global `node_addr -> {npub, display_name}` mapping.

## What Is Logged

Lookup events:
- `lookup_request_sent`
- `lookup_request_received`
- `lookup_request_forwarded`
- `lookup_response_sent`
- `lookup_response_received`
- `lookup_response_forwarded`

Tree events:
- `tree_announce_received`
- `tree_announce_rejected`
- `tree_announce_accepted`
- `local_tree_snapshot`

## Edge Types

Two edge families are derived from the event stream.

### Coord Edges

Coord edges come from ordered coordinate paths.

For a path like:

```text
[C, B, A]
```

the derived child-parent edges are:
- `C -> B`
- `B -> A`

These are the blue edges in the rendered graph.

They represent claimed or accepted tree relationships, depending on the source
event.

### Message Edges

Message edges come from lookup send/forward/receive activity.

Examples:
- `lookup_request_sent`: `observer -> to`
- `lookup_request_forwarded`: `observer -> to`
- `lookup_request_received`: `from -> observer`
- `lookup_response_sent`: `observer -> to`
- `lookup_response_forwarded`: `observer -> to`
- `lookup_response_received`: `from -> observer`

These are the orange edges in the rendered graph.

They represent actual lookup message flow over direct peer links.

## Live Persistence

Live monitoring is session-based.

Each named session writes to a stable directory:

```text
artifacts/coord-monitor/live/<session>/
```

The live collector can be stopped and restarted with the same session name.
New collector invocations append to the same raw logs and JSONL files.

Invocation history is tracked in:

```text
artifacts/coord-monitor/live/<session>/state.json
```

### Start Or Resume A Live Session

```bash
./testing/static/scripts/collect-coord-monitor-live.sh my-session \
  fips-node-a fips-node-b fips-node-c
```

While running, the collector prints a short line for each event, for example:

```text
[event] fips-node-b lookup_request_forwarded
```

## Build A Graph

After stopping the live collector, build the combined graph with:

```bash
make my-session.svg
```

This reads:

```text
artifacts/coord-monitor/live/my-session/raw/*.log
```

and writes:

```text
artifacts/coord-monitor/live/my-session/post/graph/combined.svg
```

Other derived outputs are written under:

```text
artifacts/coord-monitor/live/my-session/post/
```

including:
- extracted JSONL events
- merged identity map
- aggregated coord edges
- aggregated message edges
- Graphviz DOT files

## Current Demo

The current monitoring demo is the three-node chain:

```text
A <> B <> C
```

managed by the static Docker profile:

```text
lookup-monitor-demo
```

Typical flow:

```bash
./testing/scripts/build.sh
./testing/static/scripts/generate-configs.sh lookup-monitor-demo
docker compose -f testing/static/docker-compose.yml --profile lookup-monitor-demo up -d
source testing/static/generated-configs/npubs.env
docker exec fips-node-a fipsctl lookup "$NPUB_C"
```

Expected result:
- `A` records request send and response receive
- `B` records request receive/forward and response receive/forward
- `C` records request receive and response send

## Future Experiments

The monitoring stack is being built to support later dishonest-node
experiments.

The current plan is only at a high level:
- dishonest nodes advertising fake roots
- dishonest nodes manipulating bloom-filter state, including large bloom
  filters

This document intentionally does not go deeper into those experiments yet.
