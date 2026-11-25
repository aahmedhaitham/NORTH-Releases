"""Publish a bounded private snapshot to a configured NORTH Cloud workspace."""

import asyncio
import hashlib
import json
import logging
import os
import socket
import sqlite3
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from starlette.concurrency import run_in_threadpool

from device_watch import findings
from network import snapshot
from north import build_cases, report


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_snapshot(store, neighbor_status, sysmon_status, url, router_status=None):
    events = store.events()
    cases = sorted(
        build_cases(events), key=lambda case: case["evidence"][-1]["timestamp"], reverse=True,
    )[:25]
    network = {
        **snapshot(events), "neighbors": neighbor_status, "sysmon": sysmon_status, "device_findings": findings(store),
    }
    if router_status is not None:
        network["router_usage"] = router_status
    host = socket.gethostname()
    source = os.getenv("NORTH_CLOUD_SOURCE") or "host-" + hashlib.sha256(host.encode()).hexdigest()[:16]
    label = (os.getenv("NORTH_CLOUD_LABEL") or host)[:80]
    target = hashlib.sha256((url.rstrip("/") + "|" + source).encode()).hexdigest()
    pending = store.pending_cloud_events(target)
    payload = {"source": {"id": source, "label": label},
               "cases": cases, "events": pending, "network": network,
               "reports": {case["id"]: report(case) for case in cases}}
    data = json.dumps(payload).encode()
    while len(data) > 700_000 and len(pending) > 1:
        pending = pending[:len(pending) // 2]
        payload["events"] = pending
        data = json.dumps(payload).encode()
    if len(data) > 700_000:
        raise ValueError("Collector snapshot exceeds the cloud size limit")
    return data, target, [event["id"] for event in pending]


def send_snapshot(url, key, data):
    destination = urlsplit(url)
    if (destination.scheme != "https" or not destination.hostname or destination.username or destination.password
            or destination.path not in ("", "/") or destination.query or destination.fragment):
        raise ValueError("NORTH_CLOUD_URL must be an HTTPS origin")
    request = Request(
        url.rstrip("/") + "/api/cloud/snapshot", data=data,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "User-Agent": "NORTH-Collector/1.0"},
    )
    with build_opener(NoRedirects()).open(request, timeout=12) as response:
        if response.status != 200:
            raise OSError("Cloud workspace did not accept the snapshot")


async def sync_loop(store, neighbors, sysmon, url, key, router=None):
    previous = None
    while True:
        try:
            data, target, event_ids = await run_in_threadpool(
                build_snapshot, store, neighbors.current, sysmon.current, url, router.current if router else None,
            )
            if data != previous:
                await run_in_threadpool(send_snapshot, url, key, data)
                if event_ids:
                    await run_in_threadpool(store.record_cloud_receipts, target, event_ids)
                previous = data
        except HTTPError as error:
            logging.getLogger(__name__).warning("NORTH Cloud sync was refused: HTTP %s", error.code)
        except (OSError, ValueError, sqlite3.Error) as error:
            logging.getLogger(__name__).warning("NORTH Cloud sync failed: %s", type(error).__name__)
        await asyncio.sleep(60)
