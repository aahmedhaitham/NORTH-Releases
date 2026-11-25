"""Read the host's existing neighbor cache without probing the network."""

import asyncio
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from device_watch import record_snapshot


def read_neighbors():
    if sys.platform == "win32":
        exporter = Path(__file__).resolve().parents[1] / "tools" / "Export-NorthNeighbors.ps1"
        command = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(exporter), "-AsJson",
        ]
        options = {"creationflags": subprocess.CREATE_NO_WINDOW}
    elif sys.platform.startswith("linux"):
        command = ["ip", "-j", "neigh"]
        options = {}
    else:
        raise RuntimeError("The automatic collector supports Windows and Linux hosts")
    result = subprocess.run(
        command, capture_output=True, check=True, encoding="utf-8", timeout=12, **options,
    )
    records = json.loads(result.stdout)
    if not isinstance(records, list):
        raise ValueError("Expected a list of neighbor records")
    return records


class NeighborMonitor:
    def __init__(self, store, enabled):
        self.store = store
        self.current = {
            "state": "starting" if enabled else "disabled",
            "updated_at": None,
            "records": [],
        }

    async def refresh(self):
        try:
            records = await run_in_threadpool(read_neighbors)
            observed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            await run_in_threadpool(record_snapshot, self.store, records, observed_at)
        except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.SubprocessError):
            self.current = {**self.current, "state": "unavailable"}
        else:
            self.current = {
                "state": "ready",
                "updated_at": observed_at,
                "records": records,
            }

    async def run(self):
        while True:
            await self.refresh()
            await asyncio.sleep(30)
