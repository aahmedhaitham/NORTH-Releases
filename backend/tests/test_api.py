import json
from pathlib import Path
from urllib.error import URLError

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
from north import Store, build_cases, normalize


def test_seed_websocket_report_and_offline_draft(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_SEED_DEMO", "1")

    def unavailable(*args, **kwargs):
        raise URLError("offline")

    monkeypatch.setattr(main, "urlopen", unavailable)
    with TestClient(main.make_app(Store(path=tmp_path / "test.sqlite3"))) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        case, = client.get("/api/cases").json()
        for _ in range(2):
            with client.websocket_connect("/api/live") as socket:
                assert socket.receive_json() == [case]
        url = "/api/cases/" + case["id"]
        assert client.post(url + "/draft").status_code == 503
        report = client.get(url + "/report")
        assert report.status_code == 200
        assert all(item["id"] in report.text for item in case["evidence"])
        assert client.post("/api/ingest", json={"alerts": [{}]}).status_code == 422


def test_draft_prioritizes_supported_observations():
    raw = json.loads((Path(__file__).parents[1] / "fixtures" / "demo.json").read_text())
    started, connected, wrote = [normalize(alert) for alert in raw]
    case, = build_cases([started, connected, wrote])
    findings = main.observed_findings(case)
    payload = {"response": '{"finding_ids":[2,3,2]}'}
    result = main.validated_draft(payload, findings)
    assert [claim["evidence_ids"] for claim in result["claims"]] == [
        [started["id"], wrote["id"]],
        [started["id"], connected["id"]],
    ]

    # A missing connection provides no support for a network observation.
    partial, = build_cases([started, wrote])
    findings = main.observed_findings(partial)
    assert len(findings) == 2
    with pytest.raises(HTTPException) as error:
        main.validated_draft(payload, findings)
    assert error.value.status_code == 502


def test_draft_endpoint_resolves_ranked_observations(tmp_path, monkeypatch):
    store = Store(path=tmp_path / "test.sqlite3")
    store.initialize()
    store.ingest(json.loads((Path(__file__).parents[1] / "fixtures" / "demo.json").read_text()))
    case, = build_cases(store.events())

    def respond(request, timeout):
        from io import BytesIO

        options = json.loads(request.data)
        assert options["format"]["properties"]["finding_ids"]["items"]["maximum"] == 3
        return BytesIO(b'{"response":"{\\"finding_ids\\":[3]}"}')

    monkeypatch.setattr(main, "urlopen", respond)
    route = next(route for route in main.make_app(store).routes if route.path.endswith("/draft"))
    claim, = route.endpoint(case["id"])["claims"]
    assert claim["evidence_ids"][-1] == case["links"][0]["evidence_id"]


@pytest.mark.parametrize("body", [
    '{"finding_ids":[]}',
    '{"finding_ids":[true]}',
    '{"finding_ids":[0]}',
    '{"claims":[{"text":"Malicious activity confirmed"}]}',
])
def test_draft_rejects_unverified_model_output(body):
    with pytest.raises(HTTPException) as error:
        main.validated_draft({"response": body}, [{"text": "Process started", "evidence_ids": ["a"]}])
    assert error.value.status_code == 502


def test_public_demo_blocks_write_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_PUBLIC_DEMO", "1")
    store = Store(path=tmp_path / "test.sqlite3")
    store.initialize()
    app = main.make_app(store)
    endpoints = {route.path: route.endpoint for route in app.routes}
    with pytest.raises(HTTPException) as ingest_error:
        endpoints["/api/ingest"](main.Batch(alerts=[{}]))
    with pytest.raises(HTTPException) as draft_error:
        endpoints["/api/cases/{case_id}/draft"]("example")
    assert ingest_error.value.status_code == draft_error.value.status_code == 403
    assert store.events() == []


def test_public_demo_seed_contains_both_platforms(tmp_path):
    store = Store(path=tmp_path / "demo.sqlite3")
    store.initialize()
    alerts = main.demo_alerts(include_linux=True)
    assert store.ingest(alerts) == 6
    assert store.ingest(alerts) == 0
    windows, linux = build_cases(store.events())
    assert windows["host"] == "WIN-LAB-01"
    assert linux["host"] == "KALI-DEMO"
    claim, = main.observed_findings(linux)
    assert claim["evidence_ids"] == [event["id"] for event in linux["evidence"]]
