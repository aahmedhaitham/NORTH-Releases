from types import SimpleNamespace

import main
import neighbors
from main import demo_alerts
from network import snapshot
from north import Store, normalize


def test_inventory_separates_connections_and_links_investigations():
    events = [normalize(alert) for alert in demo_alerts(include_linux=True)]
    inventory = snapshot(events[::-1])
    assert inventory == snapshot(events)
    assets = {asset["host"]: asset for asset in inventory["assets"]}
    assert assets["WIN-LAB-01"]["events"] == assets["KALI-DEMO"]["events"] == 3
    outbound, inbound = inventory["links"]
    assert outbound["direction"] == "outbound"
    assert inbound["direction"] == "inbound"
    assert outbound["events"] == 1 and inbound["events"] == 3
    assert outbound["cases"] == assets["WIN-LAB-01"]["cases"]
    assert inbound["cases"] == assets["KALI-DEMO"]["cases"]
    assert len(inventory["activity"]["buckets"]) == 12
    assert sum(item["count"] for item in inventory["activity"]["buckets"]) == 6
    assert {item["kind"]: item["count"] for item in inventory["activity"]["types"]} == {1: 1, 3: 1, 11: 1, 1001: 3}


def test_inventory_keeps_connections_with_no_correlated_incident():
    event = normalize(demo_alerts()[1])
    inventory = snapshot([event])
    assert inventory["links"][0]["address"] == event["destination"]
    assert inventory["links"][0]["cases"] == []


def test_linux_collector_reads_cache_without_probes(monkeypatch):
    monkeypatch.setattr(neighbors.sys, "platform", "linux")

    def run(command, **options):
        assert command == ["ip", "-j", "neigh"]
        assert options["timeout"] == 12
        return SimpleNamespace(stdout='[{"dst":"192.0.2.42","dev":"eth0"}]')

    monkeypatch.setattr(neighbors.subprocess, "run", run)
    assert neighbors.read_neighbors() == [{"dst": "192.0.2.42", "dev": "eth0"}]


def test_public_app_disables_automatic_local_collection(monkeypatch, tmp_path):
    monkeypatch.setenv("NORTH_NETWORK_AUTO", "1")
    monkeypatch.setenv("NORTH_SYSMON_AUTO", "1")
    monkeypatch.setenv("NORTH_PUBLIC_DEMO", "1")
    store = Store(path=tmp_path / "public.sqlite3")
    store.initialize()
    route = next(route for route in main.make_app(store).routes if route.path == "/api/network")
    assert route.endpoint()["neighbors"] == {"state": "disabled", "updated_at": None, "records": []}
    assert route.endpoint()["sysmon"]["state"] == "disabled"
