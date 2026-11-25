"""Track newly observed MAC addresses from a private neighbor-cache collector."""

import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address


def observed_devices(records):
    devices = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        network = record.get("interface") or record.get("dev")
        if not isinstance(network, str) or not network.strip():
            continue
        if re.search(r"vmware|virtualbox|vethernet|^veth|^docker", network, re.IGNORECASE):
            continue
        raw_mac = record.get("mac") or record.get("lladdr") or ""
        if not isinstance(raw_mac, str):
            continue
        mac = re.sub(r"[:-]", "", raw_mac.lower())
        if not re.fullmatch(r"[0-9a-f]{12}", mac) or mac == "0" * 12 or int(mac[:2], 16) & 1:
            continue
        raw_ip = record.get("address") or record.get("dst")
        if not isinstance(raw_ip, str):
            continue
        try:
            address = ip_address(raw_ip)
        except ValueError:
            continue
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            continue
        fingerprint = hashlib.sha256(json.dumps([network, mac]).encode()).hexdigest()[:24]
        device = devices.setdefault(fingerprint, {
            "mac": ":".join(mac[index:index + 2] for index in range(0, 12, 2)),
            "interface": network,
            "addresses": set(),
        })
        device["addresses"].add(str(address))
    return devices


def record_snapshot(store, records, observed_at):
    devices = observed_devices(records)
    if not devices:
        return
    marker = "%s" if store.url else "?"
    placeholders = ", ".join([marker] * 5)
    with store.connect() as db:
        seeded_baseline = db.execute(
            f"INSERT INTO neighbor_baseline (scope, started_at) VALUES ('local', {marker}) "
            "ON CONFLICT (scope) DO NOTHING", (observed_at,),
        ).rowcount
        for device_id, device in devices.items():
            payload = {**device, "addresses": sorted(device["addresses"])}
            db.execute(
                f"INSERT INTO neighbor_devices (id, first_seen, last_seen, payload, baseline) VALUES ({placeholders}) "
                "ON CONFLICT (id) DO UPDATE SET last_seen = excluded.last_seen, payload = excluded.payload "
                "WHERE excluded.last_seen >= neighbor_devices.last_seen",
                (device_id, observed_at, observed_at, json.dumps(payload), seeded_baseline),
            )


def findings(store):
    with store.connect() as db:
        baseline = db.execute("SELECT started_at FROM neighbor_baseline WHERE scope = 'local'").fetchone()
        count, = db.execute(
            "SELECT COUNT(*) FROM neighbor_devices WHERE baseline = 0 AND reviewed_at IS NULL"
        ).fetchone()
        rows = db.execute(
            "SELECT id, first_seen, last_seen, payload, reviewed_at FROM neighbor_devices "
            "WHERE baseline = 0 ORDER BY CASE WHEN reviewed_at IS NULL THEN 0 ELSE 1 END, "
            "first_seen DESC, id DESC LIMIT 50"
        ).fetchall()
    return {
        "baseline_at": baseline[0] if baseline else None, "unreviewed": count,
        "items": [
            {"id": device_id, "first_seen": first, "last_seen": last, "reviewed_at": reviewed,
             **json.loads(payload)}
            for device_id, first, last, payload, reviewed in rows
        ],
    }


def mark_reviewed(store, device_id):
    marker = "%s" if store.url else "?"
    timestamp = datetime.now(timezone.utc).isoformat()
    with store.connect() as db:
        return bool(db.execute(
            f"UPDATE neighbor_devices SET reviewed_at = COALESCE(reviewed_at, {marker}) "
            f"WHERE id = {marker} AND baseline = 0",
            (timestamp, device_id),
        ).rowcount)


def demo_findings():
    baseline = "2026-01-15T10:00:00.000000+00:00"
    first = "2026-01-15T10:05:00.000000+00:00"
    return {
        "baseline_at": baseline, "unreviewed": 1,
        "items": [
            {"id": "portfolio-device", "first_seen": first, "last_seen": first, "reviewed_at": None,
             "mac": "02:00:00:00:00:42", "interface": "Demo LAN", "addresses": ["192.0.2.42"]},
        ],
    }
