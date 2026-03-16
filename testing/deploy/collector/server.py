#!/usr/bin/env python3
"""FIPS topology collector — stores raw reports in SQLite.

Listens on [::]:8080.

  POST /report  — store a JSON report (status + tree + peers)
  GET  /reports — list recent reports (last 100)
  GET  /health  — liveness check

Usage:
    python3 server.py [db_path]
    Default db_path: /data/collector.db
"""

import json
import socket
import sqlite3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

DB_PATH = sys.argv[1] if len(sys.argv) > 1 else "/data/collector.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY,
            received_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            body TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_received_at ON reports(received_at)")
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/report":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}\n')
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")

        if not body:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "empty body"}\n')
            return

        conn = sqlite3.connect(DB_PATH)
        cur = conn.execute("INSERT INTO reports (body) VALUES (?)", (body,))
        report_id = cur.lastrowid
        conn.commit()
        conn.close()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "id": report_id}).encode() + b"\n")

    def do_GET(self):
        if self.path == "/":
            try:
                with open("/opt/collector/push.sh", "r") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(content.encode())
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Error reading push.sh: {e}\n".encode())
                return

        if self.path == "/reports":
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT id, received_at FROM reports ORDER BY id DESC LIMIT 100"
            ).fetchall()
            conn.close()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            result = [{"id": r[0], "received_at": r[1]} for r in rows]
            self.wfile.write(json.dumps(result, indent=2).encode() + b"\n")
            return

        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}\n')
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'{"error": "not found"}\n')

    def log_message(self, format, *args):
        print(f"[collector] {args[0]}")


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6


if __name__ == "__main__":
    init_db()
    server = HTTPServerV6(("::", 8080), Handler)
    print(f"[collector] listening on [::]:8080, db={DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
