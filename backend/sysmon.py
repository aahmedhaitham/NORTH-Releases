"""Collect configured Windows Sysmon events using a durable record cursor."""

import asyncio
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from starlette.concurrency import run_in_threadpool


SOURCE = "windows-sysmon"


def collection_problem(error):
    if isinstance(error, subprocess.CalledProcessError):
        detail = error.stderr or ""
        if "UnauthorizedAccessException" in detail:
            return "access_denied"
        if "NoMatchingLogsFound" in detail:
            return "channel_missing"
    return "read_failed"


def collect(store):
    after = store.collection_offset(SOURCE)
    reader = Path(__file__).resolve().parents[1] / "tools" / "Read-NorthSysmon.ps1"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(reader), "-After", str(after)],
        capture_output=True, check=True, encoding="utf-8", timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    batch = json.loads(result.stdout)
    position, alerts = batch["position"], batch["alerts"]
    if type(position) is not int or position < 0 or not isinstance(alerts, list) or len(alerts) > 500:
        raise ValueError("Invalid Sysmon collection batch")
    return store.ingest(alerts, checkpoint=(SOURCE, position)), len(alerts)


class SysmonMonitor:
    def __init__(self, store, enabled):
        self.store = store
        self.current = {
            "state": "starting" if enabled else "disabled",
            "updated_at": None,
            "session_events": 0,
            "problem": None,
        }

    async def run(self):
        while True:
            try:
                inserted, read = await run_in_threadpool(collect, self.store)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error, subprocess.SubprocessError) as error:
                self.current = {**self.current, "state": "unavailable", "problem": collection_problem(error)}
                read = 0
            else:
                self.current = {
                    "state": "ready",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "session_events": self.current["session_events"] + inserted,
                    "problem": None,
                }
            await asyncio.sleep(1 if read == 500 else 15)
