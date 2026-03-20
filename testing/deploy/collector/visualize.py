#!/usr/bin/env python3
"""Visualize the FIPS mesh topology from collected reports.

Reads all reports from the SQLite database, merges them into a unified
graph, and outputs a Graphviz DOT file (piped through `dot -Tsvg` if
available).

Node inclusion:  Every node that ever appeared in any report.
Edge types:
  - Current tree edge (solid black)   — parent/child in latest report
  - Historical tree edge (solid orange) — was tree edge in past, not now
  - Non-tree link (dashed gray)        — never a tree edge

Usage:
    python3 visualize.py [db_path] > mesh.svg
    python3 visualize.py [db_path] --dot > mesh.dot   # DOT only, no SVG
"""

import json
import sqlite3
import subprocess
import sys
from collections import defaultdict


DB_PATH = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "data/collector.db"
DOT_ONLY = "--dot" in sys.argv


def load_reports(db_path):
    """Load all reports from the database, ordered oldest first."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, received_at, body FROM reports ORDER BY id ASC"
    ).fetchall()
    conn.close()

    reports = []
    for row_id, received_at, body in rows:
        try:
            data = json.loads(body)
            reports.append((row_id, received_at, data))
        except json.JSONDecodeError:
            print(f"[warn] skipping report {row_id}: invalid JSON", file=sys.stderr)
    return reports


def build_graph(reports):
    """Build a merged graph from all reports.

    Returns:
        nodes: dict of node_addr -> {display_name, node_addr, depth, is_reporter, npub}
        edges: dict of (node_addr_a, node_addr_b) -> {ever_tree, current_tree, rtt, direction}
    """
    nodes = {}  # node_addr -> info
    display_names = {}  # node_addr -> name (from peer data only)
    edges = {}  # frozenset(addr_a, addr_b) -> info
    reporter_addrs = set()

    # Track latest report per reporter for "current" classification
    latest_report_per_node = {}  # node_addr -> (report_id, data)

    for report_id, received_at, data in reports:
        status = data.get("status", {})
        tree = data.get("tree", {})
        peers_data = data.get("peers", {})
        peers_list = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

        reporter_addr = tree.get("my_node_addr") or status.get("node_addr")
        if not reporter_addr:
            continue

        reporter_npub = status.get("npub", "")
        reporter_depth = tree.get("depth")
        reporter_addrs.add(reporter_addr)

        # Register the reporter node
        nodes[reporter_addr] = {
            "node_addr": reporter_addr,
            "depth": reporter_depth,
            "is_reporter": True,
            "npub": reporter_npub,
        }

        latest_report_per_node[reporter_addr] = (report_id, data)

        # Register all peers as nodes
        for peer in peers_list:
            peer_addr = peer.get("node_addr")
            if not peer_addr:
                continue

            # Peer-assigned display names are the authority
            peer_name = peer.get("display_name")
            if peer_name:
                display_names[peer_addr] = peer_name

            peer_npub = peer.get("npub", "")
            peer_depth = peer.get("tree_depth")

            existing = nodes.get(peer_addr, {})
            nodes[peer_addr] = {
                "node_addr": peer_addr,
                "depth": peer_depth if peer_depth is not None else existing.get("depth"),
                "is_reporter": existing.get("is_reporter", False),
                "npub": peer_npub or existing.get("npub", ""),
            }

            # Register the edge
            edge_key = frozenset([reporter_addr, peer_addr])
            is_tree = peer.get("is_parent", False) or peer.get("is_child", False)
            rtt = peer.get("mmp", {}).get("srtt_ms")

            transport_type = peer.get("transport_type", "")

            if edge_key not in edges:
                edges[edge_key] = {
                    "ever_tree": False,
                    "current_tree": False,
                    "rtt": None,
                    "transport_type": "",
                    # Track parent->child direction for tree edges
                    "parent": None,
                    "child": None,
                }

            if transport_type:
                edges[edge_key]["transport_type"] = transport_type

            if is_tree:
                edges[edge_key]["ever_tree"] = True
                if peer.get("is_parent"):
                    edges[edge_key]["parent"] = peer_addr
                    edges[edge_key]["child"] = reporter_addr
                elif peer.get("is_child"):
                    edges[edge_key]["parent"] = reporter_addr
                    edges[edge_key]["child"] = peer_addr

            if rtt is not None:
                edges[edge_key]["rtt"] = rtt

        # Also register peers from the tree.peers list (has coords/depth)
        for tree_peer in tree.get("peers", []):
            tp_addr = tree_peer.get("node_addr")
            if not tp_addr:
                continue
            tp_name = tree_peer.get("display_name")
            if tp_name:
                display_names[tp_addr] = tp_name
            if tp_addr not in nodes:
                nodes[tp_addr] = {
                    "node_addr": tp_addr,
                    "depth": tree_peer.get("depth"),
                    "is_reporter": False,
                    "npub": "",
                }

    # Apply display names: peer-assigned alias, or truncated node_addr
    for addr, info in nodes.items():
        info["display_name"] = display_names.get(addr) or addr[:12] + "..."

    # Now determine "current" tree edges from latest reports only
    # First, reset all current_tree flags
    for edge_key in edges:
        edges[edge_key]["current_tree"] = False

    for reporter_addr, (report_id, data) in latest_report_per_node.items():
        peers_data = data.get("peers", {})
        peers_list = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

        for peer in peers_list:
            peer_addr = peer.get("node_addr")
            if not peer_addr:
                continue

            edge_key = frozenset([reporter_addr, peer_addr])
            is_tree = peer.get("is_parent", False) or peer.get("is_child", False)

            if is_tree and edge_key in edges:
                edges[edge_key]["current_tree"] = True
                # Update direction from latest
                if peer.get("is_parent"):
                    edges[edge_key]["parent"] = peer_addr
                    edges[edge_key]["child"] = reporter_addr
                elif peer.get("is_child"):
                    edges[edge_key]["parent"] = reporter_addr
                    edges[edge_key]["child"] = peer_addr

                # Update RTT and transport type from latest
                rtt = peer.get("mmp", {}).get("srtt_ms")
                if rtt is not None:
                    edges[edge_key]["rtt"] = rtt

                transport_type = peer.get("transport_type", "")
                if transport_type:
                    edges[edge_key]["transport_type"] = transport_type

    return nodes, edges


def node_id(node_addr):
    """Make a valid DOT node identifier from a node_addr."""
    return "n_" + node_addr.replace(":", "")


def generate_dot(nodes, edges):
    """Generate a Graphviz DOT string."""
    # Find the root (smallest node_addr, or depth=0)
    root_addr = None
    for addr, info in nodes.items():
        if info.get("depth") == 0:
            root_addr = addr
            break
    if root_addr is None:
        root_addr = min(nodes.keys())

    lines = []
    lines.append("digraph fips_mesh {")
    lines.append("    rankdir=TB")
    lines.append("    bgcolor=white")
    lines.append('    node [shape=box, style=rounded, fontname="Helvetica", fontsize=11]')
    lines.append('    edge [fontname="Helvetica", fontsize=9]')
    lines.append("")

    # Nodes
    for addr, info in sorted(nodes.items(), key=lambda x: x[1].get("depth") or 99):
        nid = node_id(addr)
        name = info["display_name"]
        npub = info.get("npub", "")
        short_npub = f"{npub[:12]}...{npub[-6:]}" if len(npub) > 20 else npub
        short_addr = addr[:12] + "..."
        depth = info.get("depth")
        depth_str = f"depth={depth}" if depth is not None else ""

        label = f"{name}"
        if short_npub:
            label += f"\\n{short_npub}"
        label += f"\\n{short_addr}"
        if depth_str:
            label += f"\\n{depth_str}"

        styles = ["rounded"]
        if addr == root_addr:
            styles.append("bold")
            label += "\\n(root)"
        if not info.get("is_reporter"):
            styles.append("dotted")

        style = ",".join(styles)
        lines.append(f'    {nid} [label="{label}", style="{style}"]')

    lines.append("")

    # Edges
    seen_edges = set()
    for edge_key, info in edges.items():
        addrs = sorted(edge_key)
        edge_id = (addrs[0], addrs[1])
        if edge_id in seen_edges:
            continue
        seen_edges.add(edge_id)

        rtt_str = f"{info['rtt']:.1f}ms" if info.get("rtt") is not None else ""
        transport_str = info.get("transport_type", "")
        label_parts = [p for p in [rtt_str, transport_str] if p]
        rtt_label = "\\n".join(label_parts)

        if info["current_tree"]:
            # Current tree edge: solid black, directed parent->child
            parent = info.get("parent")
            child = info.get("child")
            if parent and child:
                from_node = node_id(parent)
                to_node = node_id(child)
            else:
                from_node = node_id(addrs[0])
                to_node = node_id(addrs[1])

            lines.append(
                f'    {from_node} -> {to_node} '
                f'[label="{rtt_label}", color=black, penwidth=2.0]'
            )
        elif info["ever_tree"]:
            # Historical tree edge: solid orange, directed
            parent = info.get("parent")
            child = info.get("child")
            if parent and child:
                from_node = node_id(parent)
                to_node = node_id(child)
            else:
                from_node = node_id(addrs[0])
                to_node = node_id(addrs[1])

            lines.append(
                f'    {from_node} -> {to_node} '
                f'[label="{rtt_label}", color=orange, penwidth=1.5]'
            )
        else:
            # Non-tree link: dashed gray, undirected
            a = node_id(addrs[0])
            b = node_id(addrs[1])
            lines.append(
                f'    {a} -> {b} '
                f'[label="{rtt_label}", style=dashed, dir=none, color=gray, penwidth=1.0]'
            )

    lines.append("}")
    return "\n".join(lines)


def main():
    reports = load_reports(DB_PATH)
    if not reports:
        print("No reports found in database.", file=sys.stderr)
        sys.exit(1)

    print(f"[info] loaded {len(reports)} reports", file=sys.stderr)

    nodes, edges = build_graph(reports)
    print(f"[info] {len(nodes)} nodes, {len(edges)} edges", file=sys.stderr)

    dot = generate_dot(nodes, edges)

    if DOT_ONLY:
        print(dot)
    else:
        try:
            result = subprocess.run(
                ["dot", "-Tsvg"],
                input=dot.encode(),
                capture_output=True,
                check=True,
            )
            sys.stdout.buffer.write(result.stdout)
        except FileNotFoundError:
            print("[error] 'dot' not found. Install graphviz: apt install graphviz", file=sys.stderr)
            print("[info] outputting DOT instead:", file=sys.stderr)
            print(dot)
            sys.exit(1)


if __name__ == "__main__":
    main()
