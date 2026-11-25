"""Summarize observed assets and network relationships from stored telemetry."""

from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address

from north import SSH_FAILURE, build_cases


def activity(events):
    if not events:
        return {"buckets": [], "types": [], "interval": None}
    times = [int(datetime.fromisoformat(event["timestamp"]).timestamp()) for event in events]
    latest = max(times)
    span = latest - min(times)
    seconds, label = (60, "minute") if span < 3600 else (3600, "hour") if span < 86400 else (86400, "day")
    end = latest - latest % seconds
    start = end - 11 * seconds
    counts = Counter(timestamp - timestamp % seconds for timestamp in times if timestamp >= start)
    types = Counter(event["kind"] for event in events)
    return {
        "interval": label,
        "buckets": [
            {"start": datetime.fromtimestamp(index, timezone.utc).isoformat(), "count": counts[index]}
            for index in range(start, end + seconds, seconds)
        ],
        "types": [
            {"kind": kind, "count": count}
            for kind, count in sorted(types.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


def snapshot(events):
    case_refs = {}
    for case in build_cases(events):
        ref = {"id": case["id"], "title": case["title"]}
        for event in case["evidence"]:
            case_refs.setdefault(event["id"], {})[case["id"]] = ref

    assets = {}
    links = {}
    for event in events:
        asset_id = event["asset_id"]
        asset = assets.setdefault(asset_id, {
            "id": asset_id, "host": event["host"], "events": 0,
            "last_seen": event["timestamp"], "cases": {},
        })
        asset["events"] += 1
        if event["timestamp"] >= asset["last_seen"]:
            asset["last_seen"] = event["timestamp"]
            asset["host"] = event["host"]
        refs = case_refs.get(event["id"], {})
        asset["cases"].update(refs)

        inbound = event["kind"] == SSH_FAILURE
        candidate = event.get("source_ip") if inbound else event["destination"] if event["kind"] == 3 else None
        if not candidate:
            continue
        try:
            address = str(ip_address(candidate))
        except ValueError:
            continue
        direction = "inbound" if inbound else "outbound"
        key = (asset_id, address, direction)
        link = links.setdefault(key, {
            "asset_id": asset_id, "address": address, "direction": direction,
            "events": 0, "last_seen": event["timestamp"], "cases": {},
            "source": "OpenSSH" if inbound else "Sysmon",
        })
        link["events"] += 1
        link["last_seen"] = max(link["last_seen"], event["timestamp"])
        link["cases"].update(refs)

    def with_cases(item):
        return {**item, "cases": sorted(item["cases"].values(), key=lambda ref: (ref["title"], ref["id"]))}

    return {
        "assets": [with_cases(asset) for _, asset in sorted(assets.items())],
        "links": [with_cases(link) for _, link in sorted(links.items())],
        "activity": activity(events),
    }
