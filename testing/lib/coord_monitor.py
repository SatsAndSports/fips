#!/usr/bin/env python3
"""Persist and derive artifacts from full_coord_monitoring logs.

This tool supports two sources:

- `--from-docker <container> ...` to export raw logs directly from running
  containers
- `--from-raw <path> ...` to re-process previously saved raw log files

It writes a run directory containing raw logs, extracted JSONL events,
derived identity/edge tables, and Graphviz DOT files.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def now_ms() -> int:
    return int(time.time() * 1000)


def parse_coord_monitor_line(raw_line: str) -> tuple[dict | None, str | None, str | None]:
    """Return (event, cleaned_line, error) for a single coord-monitor log line.

    - `event` is the parsed JSON payload when present and valid
    - `cleaned_line` is the ANSI-stripped line when it matches the coord-monitor target
    - `error` is a parse error string when JSON extraction failed
    """
    line = strip_ansi(raw_line)
    if "full_coord_monitoring" not in line or "payload=" not in line:
        return None, None, None

    payload = line.split("payload=", 1)[1].strip()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        return None, line, str(exc)

    return event, line, None


def short_addr(node_addr: str) -> str:
    return node_addr if len(node_addr) <= 12 else f"{node_addr[:8]}..."


def collect_docker_logs(containers: list[str]) -> dict[str, str]:
    logs: dict[str, str] = {}
    for name in containers:
        result = subprocess.run(
            ["docker", "logs", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker logs failed for {name}: {result.stderr.strip()}")
        raw = result.stdout + result.stderr
        logs[name] = strip_ansi(raw)
    return logs


def load_raw_logs(paths: list[Path]) -> dict[str, str]:
    logs: dict[str, str] = {}
    for path in paths:
        logs[path.stem] = strip_ansi(path.read_text())
    return logs


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for item in items:
            f.write(json.dumps(item, sort_keys=True))
            f.write("\n")


def extract_events(log_text: str, source: str, run_id: str) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    rejects: list[dict] = []

    for lineno, raw_line in enumerate(log_text.splitlines(), start=1):
        event, line, error = parse_coord_monitor_line(raw_line)
        if line is None and event is None and error is None:
            continue
        if error is not None:
            rejects.append(
                {
                    "source": source,
                    "run_id": run_id,
                    "line_number": lineno,
                    "error": error,
                    "raw_line": line,
                }
            )
            continue

        event["container"] = source
        event["run_id"] = run_id
        events.append(event)

    return events, rejects


def build_identity_map(events: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    identities: dict[str, dict] = {}
    conflicts: list[dict] = []

    for event in events:
        observed = event.get("observed_at_ms")
        container = event.get("container")
        event_name = event.get("event")

        for node_addr, meta in event.get("identities", {}).items():
            entry = identities.setdefault(
                node_addr,
                {
                    "node_addr": node_addr,
                    "npub": None,
                    "display_name": None,
                    "first_seen_ms": observed,
                    "last_seen_ms": observed,
                    "seen_in_containers": set(),
                    "seen_in_events": set(),
                },
            )

            if observed is not None:
                if entry["first_seen_ms"] is None or observed < entry["first_seen_ms"]:
                    entry["first_seen_ms"] = observed
                if entry["last_seen_ms"] is None or observed > entry["last_seen_ms"]:
                    entry["last_seen_ms"] = observed

            if container:
                entry["seen_in_containers"].add(container)
            if event_name:
                entry["seen_in_events"].add(event_name)

            npub = meta.get("npub")
            if npub:
                if entry["npub"] is None:
                    entry["npub"] = npub
                elif entry["npub"] != npub:
                    conflicts.append(
                        {
                            "node_addr": node_addr,
                            "existing_npub": entry["npub"],
                            "new_npub": npub,
                            "container": container,
                            "event": event_name,
                        }
                    )

            display_name = meta.get("display_name")
            if display_name:
                current = entry["display_name"]
                if current is None or current == short_addr(node_addr):
                    entry["display_name"] = display_name

    for entry in identities.values():
        entry["seen_in_containers"] = sorted(entry["seen_in_containers"])
        entry["seen_in_events"] = sorted(entry["seen_in_events"])

    return identities, conflicts


def derive_coord_edges(events: list[dict]) -> list[dict]:
    edges: list[dict] = []
    for event in events:
        coords = event.get("coords")
        if not isinstance(coords, list) or len(coords) < 2:
            continue

        for child, parent in zip(coords, coords[1:]):
            edges.append(
                {
                    "run_id": event.get("run_id"),
                    "container": event.get("container"),
                    "observed_at_ms": event.get("observed_at_ms"),
                    "event": event.get("event"),
                    "coords_kind": event.get("coords_kind"),
                    "observer": event.get("observer"),
                    "request_id": event.get("request_id"),
                    "child": child,
                    "parent": parent,
                }
            )

    return edges


def derive_message_edges(events: list[dict]) -> list[dict]:
    edges: list[dict] = []
    received = {"lookup_request_received", "lookup_response_received"}
    sent = {
        "lookup_request_sent",
        "lookup_request_forwarded",
        "lookup_response_sent",
        "lookup_response_forwarded",
    }

    for event in events:
        event_name = event.get("event")
        src = dst = None
        if event_name in received:
            src = event.get("from")
            dst = event.get("observer")
        elif event_name in sent:
            src = event.get("observer")
            dst = event.get("to")

        if not src or not dst:
            continue

        edges.append(
            {
                "run_id": event.get("run_id"),
                "container": event.get("container"),
                "observed_at_ms": event.get("observed_at_ms"),
                "event": event_name,
                "request_id": event.get("request_id"),
                "target": event.get("target"),
                "observer": event.get("observer"),
                "src": src,
                "dst": dst,
            }
        )

    return edges


def aggregate_coord_edges(edges: list[dict]) -> list[dict]:
    agg: dict[tuple[str, str], dict] = {}
    for edge in edges:
        key = (edge["child"], edge["parent"])
        entry = agg.setdefault(
            key,
            {
                "child": edge["child"],
                "parent": edge["parent"],
                "count": 0,
                "first_seen_ms": edge.get("observed_at_ms"),
                "last_seen_ms": edge.get("observed_at_ms"),
                "events": set(),
                "coords_kinds": set(),
                "containers": set(),
                "request_ids": set(),
            },
        )
        entry["count"] += 1
        observed = edge.get("observed_at_ms")
        if observed is not None:
            if entry["first_seen_ms"] is None or observed < entry["first_seen_ms"]:
                entry["first_seen_ms"] = observed
            if entry["last_seen_ms"] is None or observed > entry["last_seen_ms"]:
                entry["last_seen_ms"] = observed
        if edge.get("event"):
            entry["events"].add(edge["event"])
        if edge.get("coords_kind"):
            entry["coords_kinds"].add(edge["coords_kind"])
        if edge.get("container"):
            entry["containers"].add(edge["container"])
        if edge.get("request_id") is not None:
            entry["request_ids"].add(edge["request_id"])

    result = []
    for entry in agg.values():
        entry["events"] = sorted(entry["events"])
        entry["coords_kinds"] = sorted(entry["coords_kinds"])
        entry["containers"] = sorted(entry["containers"])
        entry["request_ids"] = sorted(entry["request_ids"])
        result.append(entry)

    return sorted(result, key=lambda e: (e["child"], e["parent"]))


def aggregate_message_edges(edges: list[dict]) -> list[dict]:
    agg: dict[tuple[str, str], dict] = {}
    for edge in edges:
        key = (edge["src"], edge["dst"])
        entry = agg.setdefault(
            key,
            {
                "src": edge["src"],
                "dst": edge["dst"],
                "count": 0,
                "count_by_event": Counter(),
                "first_seen_ms": edge.get("observed_at_ms"),
                "last_seen_ms": edge.get("observed_at_ms"),
                "containers": set(),
                "request_ids": set(),
                "targets": set(),
            },
        )
        entry["count"] += 1
        if edge.get("event"):
            entry["count_by_event"][edge["event"]] += 1
        observed = edge.get("observed_at_ms")
        if observed is not None:
            if entry["first_seen_ms"] is None or observed < entry["first_seen_ms"]:
                entry["first_seen_ms"] = observed
            if entry["last_seen_ms"] is None or observed > entry["last_seen_ms"]:
                entry["last_seen_ms"] = observed
        if edge.get("container"):
            entry["containers"].add(edge["container"])
        if edge.get("request_id") is not None:
            entry["request_ids"].add(edge["request_id"])
        if edge.get("target"):
            entry["targets"].add(edge["target"])

    result = []
    for entry in agg.values():
        entry["count_by_event"] = dict(sorted(entry["count_by_event"].items()))
        entry["containers"] = sorted(entry["containers"])
        entry["request_ids"] = sorted(entry["request_ids"])
        entry["targets"] = sorted(entry["targets"])
        result.append(entry)

    return sorted(result, key=lambda e: (e["src"], e["dst"]))


def build_nodes(
    identity_map: dict[str, dict], coord_edges: list[dict], message_edges: list[dict]
) -> list[dict]:
    node_addrs: set[str] = set(identity_map)
    for edge in coord_edges:
        node_addrs.add(edge["child"])
        node_addrs.add(edge["parent"])
    for edge in message_edges:
        node_addrs.add(edge["src"])
        node_addrs.add(edge["dst"])

    nodes = []
    for node_addr in sorted(node_addrs):
        meta = identity_map.get(
            node_addr,
            {
                "display_name": short_addr(node_addr),
                "npub": None,
                "first_seen_ms": None,
                "last_seen_ms": None,
                "seen_in_containers": [],
                "seen_in_events": [],
            },
        )
        nodes.append(
            {
                "node_addr": node_addr,
                "display_name": meta.get("display_name") or short_addr(node_addr),
                "npub": meta.get("npub"),
                "first_seen_ms": meta.get("first_seen_ms"),
                "last_seen_ms": meta.get("last_seen_ms"),
                "seen_in_containers": meta.get("seen_in_containers", []),
                "seen_in_events": meta.get("seen_in_events", []),
            }
        )

    return nodes


def dot_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def node_label(node: dict) -> str:
    parts = [node.get("display_name") or short_addr(node["node_addr"])]
    if node.get("npub"):
        parts.append(node["npub"])
    parts.append(short_addr(node["node_addr"]))
    return "\n".join(parts)


def write_dot(
    path: Path,
    nodes: list[dict],
    coord_edges: list[dict],
    message_edges: list[dict],
    include_coord: bool,
    include_message: bool,
) -> None:
    lines = [
        "digraph coord_monitor {",
        "  graph [overlap=false, splines=true, rankdir=LR];",
        '  node [shape=box, style="rounded,filled", fillcolor="white", fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
    ]

    for node in nodes:
        label = dot_quote(node_label(node))
        lines.append(f'  "{node["node_addr"]}" [label="{label}"];')

    if include_coord:
        for edge in coord_edges:
            label = dot_quote(f"coord x{edge['count']}")
            lines.append(
                f'  "{edge["child"]}" -> "{edge["parent"]}" '
                f'[color="blue", penwidth=2.0, label="{label}"];'
            )

    if include_message:
        for edge in message_edges:
            label = dot_quote(f"msg x{edge['count']}")
            lines.append(
                f'  "{edge["src"]}" -> "{edge["dst"]}" '
                f'[color="darkorange", style="dashed", constraint=false, label="{label}"];'
            )

    lines.append("}")
    write_text(path, "\n".join(lines) + "\n")


def process_logs(
    logs: dict[str, str],
    run_dir: Path,
    run_id: str,
    topology: str,
    source_kind: str,
) -> None:
    raw_dir = run_dir / "raw"
    events_dir = run_dir / "events"
    derived_dir = run_dir / "derived"
    graph_dir = run_dir / "graph"

    all_events: list[dict] = []
    all_rejects: list[dict] = []

    for source, log_text in logs.items():
        write_text(raw_dir / f"{source}.log", log_text)
        events, rejects = extract_events(log_text, source, run_id)
        events.sort(key=lambda e: (e.get("observed_at_ms") or 0, e.get("event", "")))
        write_jsonl(events_dir / f"{source}.jsonl", events)
        all_events.extend(events)
        all_rejects.extend(rejects)

    all_events.sort(
        key=lambda e: (
            e.get("observed_at_ms") or 0,
            e.get("container", ""),
            e.get("event", ""),
        )
    )
    write_jsonl(events_dir / "merged.jsonl", all_events)
    write_jsonl(events_dir / "rejects.jsonl", all_rejects)

    identity_map, identity_conflicts = build_identity_map(all_events)
    write_json(
        derived_dir / "identity_map.json",
        {
            "count": len(identity_map),
            "conflicts": identity_conflicts,
            "identities": identity_map,
        },
    )

    coord_edges = derive_coord_edges(all_events)
    message_edges = derive_message_edges(all_events)
    write_jsonl(derived_dir / "coord_edges.jsonl", coord_edges)
    write_jsonl(derived_dir / "message_edges.jsonl", message_edges)

    coord_edges_agg = aggregate_coord_edges(coord_edges)
    message_edges_agg = aggregate_message_edges(message_edges)
    write_json(
        derived_dir / "coord_edges_agg.json",
        {"count": len(coord_edges_agg), "edges": coord_edges_agg},
    )
    write_json(
        derived_dir / "message_edges_agg.json",
        {"count": len(message_edges_agg), "edges": message_edges_agg},
    )

    nodes = build_nodes(identity_map, coord_edges_agg, message_edges_agg)
    write_json(derived_dir / "nodes.json", {"count": len(nodes), "nodes": nodes})

    write_dot(graph_dir / "coord-only.dot", nodes, coord_edges_agg, message_edges_agg, True, False)
    write_dot(
        graph_dir / "message-only.dot",
        nodes,
        coord_edges_agg,
        message_edges_agg,
        False,
        True,
    )
    write_dot(graph_dir / "combined.dot", nodes, coord_edges_agg, message_edges_agg, True, True)

    write_json(
        run_dir / "metadata.json",
        {
            "run_id": run_id,
            "topology": topology,
            "source": source_kind,
            "containers": sorted(logs.keys()),
            "exported_at_ms": now_ms(),
            "event_count": len(all_events),
            "reject_count": len(all_rejects),
            "coord_edge_count": len(coord_edges_agg),
            "message_edge_count": len(message_edges_agg),
            "node_count": len(nodes),
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Output run directory")
    parser.add_argument("--run-id", required=True, help="Run identifier stored in artifacts")
    parser.add_argument(
        "--topology",
        default="coord-monitor",
        help="Topology or scenario label for metadata",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--from-docker",
        nargs="+",
        metavar="CONTAINER",
        help="Collect raw logs from running Docker containers",
    )
    group.add_argument(
        "--from-raw",
        nargs="+",
        metavar="PATH",
        help="Re-process previously exported raw log files",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.from_docker:
        logs = collect_docker_logs(args.from_docker)
        source_kind = "docker"
    else:
        logs = load_raw_logs([Path(p) for p in args.from_raw])
        source_kind = "raw"

    process_logs(logs, run_dir, args.run_id, args.topology, source_kind)

    print(f"coord-monitor artifacts written to {run_dir}")
    print(f"  raw logs:      {run_dir / 'raw'}")
    print(f"  jsonl events:  {run_dir / 'events'}")
    print(f"  derived data:  {run_dir / 'derived'}")
    print(f"  graphviz dot:  {run_dir / 'graph'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
