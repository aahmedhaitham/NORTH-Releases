"""Verify a running NORTH demo through its HTTP and WebSocket gateway."""

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from websockets.sync.client import connect


def read_json(url, data=None):
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def verify(base, read_only=False):
    origin = urlsplit(base)
    websocket_url = urlunsplit((
        "wss" if origin.scheme == "https" else "ws", origin.netloc, "/api/live", "", "",
    ))
    with urlopen(base, timeout=10) as response:
        index = response.read()
        assert b"NORTH" in index and b"/manifest.webmanifest" in index
    manifest = read_json(base + "/manifest.webmanifest")
    assert manifest["display"] == "standalone"
    assert {icon["sizes"] for icon in manifest["icons"]} >= {"192x192", "512x512"}
    for icon in manifest["icons"]:
        with urlopen(base + icon["src"], timeout=10) as response:
            assert response.read(8) == b"\x89PNG\r\n\x1a\n"
    assert read_json(base + "/api/health") == {"status": "ok"}
    inventory = read_json(base + "/api/network")
    assert any(asset["host"] == "WIN-LAB-01" for asset in inventory["assets"])
    files = read_json(base + "/api/events?q=WIN-LAB-01&kind=11&limit=1")
    file_event, = files["events"]
    assert file_event["host"] == "WIN-LAB-01" and file_event["kind"] == 11
    cases = read_json(base + "/api/cases")
    case, = [item for item in cases if item["host"] == "WIN-LAB-01"]
    assert [item["kind"] for item in case["evidence"]] == [1, 3, 11]
    assert case["links"][0]["evidence_id"] == case["evidence"][1]["id"]
    checked = [case]
    if read_only:
        linux, = [item for item in cases if item["host"] == "KALI-DEMO"]
        assert len(cases) == 2, "The public demo should contain only the bundled cases"
        assert len(linux["evidence"]) == 3
        assert all(item["raw"]["_COMM"] == "sshd" for item in linux["evidence"])
        assert linux["links"][0]["direction"] == "inbound"
        assert any(asset["host"] == "KALI-DEMO" for asset in inventory["assets"])
        assert inventory["device_findings"]["unreviewed"] == 1
        checked.append(linux)

    for _ in range(2):
        with connect(websocket_url, origin=base, open_timeout=10, close_timeout=5) as socket:
            assert json.loads(socket.recv(timeout=10)) == cases

    for investigation in checked:
        with urlopen(base + f"/api/cases/{investigation['id']}/report", timeout=10) as response:
            report = response.read().decode()
            assert "attachment" in response.headers["Content-Disposition"]
            assert all(item["id"] in report for item in investigation["evidence"])

    fixture = Path(__file__).with_name("fixtures") / "demo.json"
    alerts = json.loads(fixture.read_text(encoding="utf-8"))
    if read_only:
        for endpoint, body in (
            ("/api/ingest", {"alerts": alerts}),
            (f"/api/cases/{case['id']}/draft", {}),
            ("/api/network/devices/portfolio-device/review", {"reviewed": True}),
        ):
            try:
                read_json(base + endpoint, json.dumps(body).encode())
            except HTTPError as error:
                assert error.code == 403, f"{endpoint} returned HTTP {error.code}"
            else:
                raise AssertionError(f"{endpoint} unexpectedly accepted a public request")
    else:
        assert read_json(base + "/api/ingest", json.dumps({"alerts": alerts}).encode()) == {
            "inserted": 0,
        }
    print("NORTH demo verified: index, health, evidence, WebSocket reconnect, and report.")
    print("Public write routes blocked." if read_only else "Duplicate import rejected.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="URL of the running NORTH console")
    parser.add_argument("--read-only", action="store_true", help="Verify public mode restrictions")
    args = parser.parse_args()
    verify(args.base_url.rstrip("/"), args.read_only)
