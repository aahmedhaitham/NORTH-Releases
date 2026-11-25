"""Read device byte totals from an explicitly configured OpenWrt router."""

import asyncio
import csv
import re
import subprocess
import sys
from datetime import datetime, timezone
from io import StringIO

from starlette.concurrency import run_in_threadpool


def parse_totals(output):
    rows = csv.DictReader(StringIO(output))
    if not {"mac", "rx_bytes", "tx_bytes"} <= set(rows.fieldnames or []):
        raise ValueError("Unsupported nlbw output")
    totals = []
    for row in rows:
        mac = row["mac"].lower()
        if not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac) or mac == "00:00:00:00:00:00":
            continue
        counts = [row[field] for field in ("rx_bytes", "tx_bytes")]
        if not all(value and re.fullmatch(r"[0-9]{1,16}", value) and int(value) <= 2**53 - 1 for value in counts):
            raise ValueError("Invalid router byte counter")
        rx, tx = map(int, counts)
        totals.append({"mac": mac, "download_bytes": rx, "upload_bytes": tx})
    return sorted(totals, key=lambda item: -(item["download_bytes"] + item["upload_bytes"]))[:64]


def read_totals(alias):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}", alias):
        raise ValueError("Invalid SSH host alias")
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    result = subprocess.run([
        "ssh", "-n", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=5", alias, "nlbw -c csv -g mac -o mac -s ,",
    ], capture_output=True, check=True, encoding="utf-8", timeout=12, **options)
    if len(result.stdout) > 1_000_000:
        raise ValueError("Oversized router response")
    return parse_totals(result.stdout)


class RouterUsage:
    def __init__(self, alias):
        self.alias = alias
        self.current = {"state": "starting", "updated_at": None, "devices": []}

    async def run(self):
        while True:
            try:
                devices = await run_in_threadpool(read_totals, self.alias)
            except (OSError, ValueError, subprocess.SubprocessError):
                self.current = {**self.current, "state": "unavailable"}
            else:
                self.current = {
                    "state": "ready", "updated_at": datetime.now(timezone.utc).isoformat(), "devices": devices,
                }
            await asyncio.sleep(60)
