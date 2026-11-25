from copy import deepcopy

import pytest
from fastapi import HTTPException

from main import demo_alerts, make_app
from north import Store


@pytest.fixture
def store(tmp_path):
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    store.ingest(demo_alerts(include_linux=True))
    return store


def test_page_is_newest_first_and_filters_by_kind_and_search(store):
    result = store.event_page(search="kali-demo", kind=1001, limit=2)
    assert len(result["events"]) == 2
    assert result["events"][0]["timestamp"] > result["events"][1]["timestamp"]
    next_page = store.event_page(search="KALI-DEMO", kind=1001, before=result["next"].split("|"), limit=2)
    assert len(next_page["events"]) == 1 and next_page["next"] is None
    assert next_page["events"][0]["id"] not in {event["id"] for event in result["events"]}


def test_cursor_breaks_timestamp_ties_and_search_escapes_like_metacharacters(store):
    alerts = deepcopy(demo_alerts()[:2])
    for number, alert in enumerate(alerts, start=100):
        alert["agent"]["name"] = "WIN_%"
        alert["data"]["win"]["system"]["systemTime"] = "2026-01-15T12:00:00Z"
        alert["data"]["win"]["system"]["eventRecordID"] = str(number)
    assert store.ingest(alerts) == 2
    first = store.event_page(search="WIN_%", limit=1)
    second = store.event_page(search="WIN_%", before=first["next"].split("|"), limit=1)
    assert first["events"][0]["id"] > second["events"][0]["id"]
    assert second["next"] is None
    assert store.event_page(search="%")["events"] == first["events"] + second["events"]


def test_event_route_rejects_an_invalid_cursor(store):
    endpoint = next(route.endpoint for route in make_app(store).routes if route.path == "/api/events")
    with pytest.raises(HTTPException) as error:
        endpoint(q="", kind=None, before="invalid", limit=10)
    assert error.value.status_code == 422
