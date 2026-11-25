import json

from cloud_sync import build_snapshot
from main import demo_alerts
from north import Store


def test_sync_only_skips_events_after_a_receipt_for_that_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_CLOUD_SOURCE", "win-lab")
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    store.ingest(demo_alerts())
    first, target, ids = build_snapshot(store, {}, {}, "https://north.example")
    assert json.loads(first)["source"]["id"] == "win-lab" and len(ids) == 3
    assert build_snapshot(store, {}, {}, "https://north.example")[2] == ids
    store.record_cloud_receipts(target, ids)
    store = Store(path=store.path)
    empty, same_target, pending = build_snapshot(store, {}, {}, "https://north.example/")
    assert same_target == target and not pending
    assert json.loads(empty)["cases"]
    assert build_snapshot(store, {}, {}, "https://another.example")[2] == ids
