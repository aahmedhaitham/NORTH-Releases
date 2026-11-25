import pytest
from fastapi import HTTPException

from device_watch import findings, mark_reviewed, record_snapshot
from main import DeviceReview, make_app
from north import Store


FIRST = "2026-11-25T11:00:00.000000+00:00"
SECOND = "2026-11-25T11:01:00.000000+00:00"
THIRD = "2026-11-25T11:02:00.000000+00:00"


def neighbor(address, mac, interface="Wi-Fi"):
    return {"address": address, "mac": mac, "interface": interface}


def test_first_seen_device_remains_reviewed_across_restarts(tmp_path):
    path = tmp_path / "events.sqlite3"
    store = Store(path=path)
    store.initialize()
    router = neighbor("192.0.2.1", "02-00-00-00-00-01")
    record_snapshot(store, [], FIRST)
    assert findings(store)["baseline_at"] is None
    record_snapshot(store, [router], FIRST)
    record_snapshot(store, [
        router,
        neighbor("192.0.2.42", "02-00-00-00-00-42"),
        neighbor("fe80::42", "02:00:00:00:00:42"),
        neighbor("192.0.2.5", "02:00:00:00:00:05", "VMware Network Adapter VMnet8"),
    ], SECOND)
    reopened = Store(path=path)
    assert findings(reopened)["unreviewed"] == 1
    finding, = findings(reopened)["items"]
    assert finding["addresses"] == ["192.0.2.42", "fe80::42"]
    assert mark_reviewed(reopened, finding["id"])
    record_snapshot(reopened, [neighbor("192.0.2.43", "02:00:00:00:00:42")], THIRD)
    result = findings(reopened)
    assert result["unreviewed"] == 0
    assert result["items"][0]["first_seen"] == SECOND
    assert result["items"][0]["last_seen"] == THIRD
    assert result["items"][0]["reviewed_at"]


def test_public_device_review_cannot_change_local_state(monkeypatch, tmp_path):
    monkeypatch.setenv("NORTH_PUBLIC_DEMO", "1")
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    route = next(route for route in make_app(store).routes if route.path.endswith("/review"))
    with pytest.raises(HTTPException) as error:
        route.endpoint("portfolio-device", DeviceReview(reviewed=True))
    assert error.value.status_code == 403
    assert findings(store)["baseline_at"] is None
