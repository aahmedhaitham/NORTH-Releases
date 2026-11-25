"""Collect and sync telemetry without running the development servers."""

import asyncio
import logging
import os
import sys

from cloud_sync import sync_loop
from neighbors import NeighborMonitor
from north import configured_store
from router_usage import RouterUsage
from sysmon import SysmonMonitor


async def collect():
    store = configured_store()
    store.initialize()
    neighbors = NeighborMonitor(store, True)
    sysmon = SysmonMonitor(store, sys.platform == "win32")
    alias = os.getenv("NORTH_OPENWRT_HOST")
    router = RouterUsage(alias) if alias else None
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(neighbors.run())
        if sys.platform == "win32":
            tasks.create_task(sysmon.run())
        if router:
            tasks.create_task(router.run())
        tasks.create_task(sync_loop(
            store, neighbors, sysmon, os.environ["NORTH_CLOUD_URL"], os.environ["NORTH_CLOUD_INGEST_KEY"], router,
        ))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(collect())
    except KeyboardInterrupt:
        pass
