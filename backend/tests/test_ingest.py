import json
from copy import deepcopy
from pathlib import Path

import pytest

from ingest import prepare
from north import SSH_FAILURE, Store, build_cases, report


def fixture():
    source = Path(__file__).parents[1] / "fixtures" / "demo.json"
    return json.loads(source.read_text(encoding="utf-8"))


@pytest.mark.parametrize("format", ["array", "lines", "search"])
def test_wazuh_export_formats_build_the_same_case(format, tmp_path):
    demo = fixture()
    unrelated = {"agent": {"id": "001"}, "data": {"win": {"system": {
        "eventID": "1", "channel": "System",
    }}}}
    records = [unrelated, *reversed(demo)]
    if format == "lines":
        document = "\n".join(json.dumps(item) for item in records)
    elif format == "search":
        document = json.dumps({"hits": {"hits": [{"_source": item} for item in records]}})
    else:
        document = json.dumps(records)

    alerts, events, skipped = prepare(document)
    assert (len(events), skipped) == (3, 1)
    store = Store(path=tmp_path / "preview.sqlite3")
    store.initialize()
    assert store.ingest(alerts) == 3
    assert store.ingest(alerts) == 0
    case, = build_cases(store.events())
    assert [event["kind"] for event in case["evidence"]] == [1, 3, 11]


def test_invalid_supported_event_is_reported_before_import():
    records = deepcopy(fixture())
    del records[1]["agent"]["id"]
    with pytest.raises(ValueError, match="record 2"):
        prepare(json.dumps(records))


def test_windows_and_linux_cases_share_one_store(tmp_path):
    source = Path(__file__).parents[1] / "fixtures" / "linux-ssh-demo.jsonl"
    journal = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    unrelated = {**journal[0], "MESSAGE": "Accepted publickey for demo from 192.0.2.42 port 54321 ssh2"}
    alerts, events, skipped = prepare(
        "\n".join(json.dumps(entry) for entry in [unrelated, *reversed(journal)]), "journal",
    )
    assert skipped == 1
    assert not build_cases(events[:2])
    different_source = {**events[1], "source_ip": "192.0.2.43"}
    assert not build_cases([events[0], different_source, events[2]])
    expired = {**events[0], "timestamp": "2026-11-25T00:00:00.000000+00:00"}
    assert not build_cases([expired, *events[1:]])

    store = Store(path=tmp_path / "mixed.sqlite3")
    store.initialize()
    assert store.ingest(fixture() + alerts) == 6
    assert store.ingest(alerts) == 0
    windows, linux = build_cases(store.events())
    assert [event["kind"] for event in windows["evidence"]] == [1, 3, 11]
    assert [event["kind"] for event in linux["evidence"]] == [SSH_FAILURE] * 3
    assert linux["links"][0]["direction"] == "inbound"
    assert "OpenSSH authentication failure" in report(linux)
    assert all(event["id"] in report(linux) for event in linux["evidence"])


def test_linux_sudo_entry_produces_a_case_without_ssh():
    entry = {
        "_HOSTNAME": "KALI-DEMO", "_MACHINE_ID": "synthetic-test", "_COMM": "sudo",
        "__CURSOR": "sudo-test-1", "__REALTIME_TIMESTAMP": "1768471200000000",
        "MESSAGE": "test : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/true",
    }
    alerts, events, skipped = prepare(json.dumps(entry), "journal")
    assert len(alerts) == 1 and not skipped
    case, = build_cases(events)
    assert case["title"] == "Sudo command observed"
    assert case["evidence"][0]["target"] == "true"
    assert case["links"] == []
    assert "Sudo command" in report(case)
