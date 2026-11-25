"""Check or import Wazuh Sysmon events or Linux journal records."""

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from north import build_cases, journal_activity, normalize


def prepare(content, export_format="wazuh"):
    content = content.lstrip("\ufeff").strip()
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        document = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.strip():
                try:
                    document.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {line_number}") from exc

    if isinstance(document, dict):
        hits = document.get("hits")
        document = hits.get("hits") if isinstance(hits, dict) else [document]
    if not isinstance(document, list):
        raise ValueError("Expected an event, an event array, or indexer search hits")

    alerts, events, skipped = [], [], 0
    for index, record in enumerate(document, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} is not an object")
        alert = record.get("_source", record)
        if not isinstance(alert, dict):
            raise ValueError(f"Record {index} has an invalid _source object")
        try:
            if export_format == "journal":
                supported = journal_activity(alert) is not None
                alert = {"source": "journalctl", "entry": alert}
            else:
                system = alert.get("data", {}).get("win", {}).get("system", {})
                channel = system.get("channel")
                supported = (
                    (not channel or channel.casefold() == "microsoft-windows-sysmon/operational")
                    and str(system.get("eventID")) in ("1", "3", "11")
                )
            if not supported:
                skipped += 1
                continue
            event = normalize(alert)
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Supported-looking record {index} could not be normalized: {exc}") from exc
        alerts.append(alert)
        events.append(event)
    if not alerts:
        raise ValueError(f"No supported {export_format} events found ({skipped} records skipped)")
    return alerts, events, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--format", choices=("wazuh", "journal"), default="wazuh")
    parser.add_argument("--check", action="store_true", help="Validate and preview locally without sending data")
    args = parser.parse_args()
    try:
        alerts, events, skipped = prepare(args.export.read_text(encoding="utf-8-sig"), args.format)
        unique = {event["id"]: event for event in reversed(events)}
        case_count = len(build_cases(list(unique.values())))
        print(f"Supported events: {len(alerts)}. Skipped: {skipped}. Cases in export: {case_count}.")
        if args.check:
            return
        inserted = 0
        for offset in range(0, len(alerts), 1000):
            request = Request(
                args.base_url.rstrip("/") + "/api/ingest",
                data=json.dumps({"alerts": alerts[offset:offset + 1000]}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(request, timeout=30) as response:
                inserted += json.load(response)["inserted"]
    except HTTPError as exc:
        parser.exit(1, f"Import stopped after {inserted} new alerts (HTTP {exc.code}). Repeating the import is safe.\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Import failed: {exc}\n")
    print(f"Imported {inserted} new alerts out of {len(alerts)}.")


if __name__ == "__main__":
    main()
