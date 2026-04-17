#!/usr/bin/env python3
"""Live coord-monitor collector with Docker restart awareness.

This tool tails `docker logs -f` for named containers, persists raw log lines,
extracts `coord_monitor_v2` events into JSONL in real time, and reconnects when
containers restart or are recreated.
"""

from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from coord_monitor import now_ms, parse_coord_monitor_line, write_json


def docker_inspect(container: str) -> tuple[bool, str | None]:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}} {{.Id}}", container],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False, None

    parts = result.stdout.strip().split()
    if len(parts) != 2:
        return False, None
    running = parts[0].lower() == "true"
    container_id = parts[1] if running else None
    return running, container_id


class LiveCollector:
    def __init__(self, run_dir: Path, run_id: str, containers: list[str]):
        self.run_dir = run_dir
        self.run_id = run_id
        self.containers = containers
        self.raw_dir = run_dir / "raw"
        self.events_dir = run_dir / "events"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.events_dir.mkdir(parents=True, exist_ok=True)

        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.started_at_ms = now_ms()
        self.state = {
            "run_id": run_id,
            "started_at_ms": self.started_at_ms,
            "updated_at_ms": self.started_at_ms,
            "containers": {
                name: {
                    "status": "waiting",
                    "container_id": None,
                    "attach_count": 0,
                    "events_written": 0,
                    "rejects_written": 0,
                    "last_attach_ms": None,
                    "last_event_ms": None,
                    "last_seen_log_ms": None,
                }
                for name in containers
            },
        }
        self.rejects_path = self.events_dir / "rejects.jsonl"

    def update_state(self, container: str, **fields) -> None:
        with self.lock:
            entry = self.state["containers"][container]
            entry.update(fields)
            self.state["updated_at_ms"] = now_ms()
            write_json(self.run_dir / "state.json", self.state)

    def append_jsonl(self, path: Path, value: dict) -> None:
        with self.lock:
            with path.open("a") as f:
                f.write(json.dumps(value, sort_keys=True))
                f.write("\n")

    def append_text(self, path: Path, text: str) -> None:
        with self.lock:
            with path.open("a") as f:
                f.write(text)

    def worker(self, container: str) -> None:
        raw_path = self.raw_dir / f"{container}.log"
        event_path = self.events_dir / f"{container}.jsonl"
        current_container_id: str | None = None

        while not self.stop_event.is_set():
            running, container_id = docker_inspect(container)
            if not running or not container_id:
                self.update_state(container, status="waiting", container_id=None)
                current_container_id = None
                self.stop_event.wait(1.0)
                continue

            if current_container_id != container_id:
                current_container_id = container_id
                entry = self.state["containers"][container]
                self.update_state(
                    container,
                    status="attaching",
                    container_id=container_id,
                    attach_count=entry["attach_count"] + 1,
                    last_attach_ms=now_ms(),
                )

            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--timestamps", container],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self.update_state(container, status="streaming", container_id=container_id)

            try:
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    if self.stop_event.is_set():
                        break

                    self.append_text(raw_path, raw_line)
                    self.update_state(container, last_seen_log_ms=now_ms())

                    event, cleaned_line, error = parse_coord_monitor_line(raw_line)
                    if cleaned_line is None and event is None and error is None:
                        continue

                    if error is not None:
                        reject = {
                            "run_id": self.run_id,
                            "container": container,
                            "container_id": container_id,
                            "collector_received_at_ms": now_ms(),
                            "error": error,
                            "raw_line": cleaned_line,
                        }
                        self.append_jsonl(self.rejects_path, reject)
                        entry = self.state["containers"][container]
                        self.update_state(
                            container,
                            rejects_written=entry["rejects_written"] + 1,
                        )
                        continue

                    assert event is not None
                    event["run_id"] = self.run_id
                    event["container"] = container
                    event["container_id"] = container_id
                    event["collector_received_at_ms"] = now_ms()
                    self.append_jsonl(event_path, event)
                    entry = self.state["containers"][container]
                    self.update_state(
                        container,
                        events_written=entry["events_written"] + 1,
                        last_event_ms=event["collector_received_at_ms"],
                    )
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()

            if not self.stop_event.is_set():
                self.update_state(container, status="reconnecting", container_id=current_container_id)
                self.stop_event.wait(1.0)

        self.update_state(container, status="stopped")

    def run(self) -> None:
        write_json(self.run_dir / "state.json", self.state)
        for container in self.containers:
            thread = threading.Thread(target=self.worker, args=(container,), daemon=True)
            thread.start()
            self.threads.append(thread)

        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_event.set()

        for thread in self.threads:
            thread.join(timeout=10)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Output run directory")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument(
        "--containers",
        nargs="+",
        required=True,
        metavar="CONTAINER",
        help="Docker container names to follow",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    collector = LiveCollector(run_dir, args.run_id, args.containers)

    def stop_handler(_signum, _frame):
        collector.stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    print(f"live coord-monitor collector writing to {run_dir}")
    print(f"watching containers: {', '.join(args.containers)}")
    collector.run()
    print("collector stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
