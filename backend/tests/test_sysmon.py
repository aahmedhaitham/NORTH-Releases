import json
from subprocess import CalledProcessError
from types import SimpleNamespace

import pytest

from main import demo_alerts
from north import Store
from sysmon import SOURCE, collect, collection_problem


def test_sysmon_advances_checkpoint_after_import_and_resumes(monkeypatch, tmp_path):
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    monkeypatch.setattr("sysmon.subprocess.CREATE_NO_WINDOW", 0, raising=False)
    positions = []

    def run(command, **options):
        positions.append(command[-1])
        alerts = demo_alerts() if command[-1] == "0" else []
        output = json.dumps({"position": 3, "alerts": alerts})
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr("sysmon.subprocess.run", run)
    assert collect(store) == (3, 3)
    reopened = Store(path=store.path)
    assert collect(reopened) == (0, 0)
    assert positions == ["0", "3"]
    assert len(reopened.events()) == 3


def test_invalid_batch_does_not_advance_checkpoint(tmp_path):
    store = Store(path=tmp_path / "events.sqlite3")
    store.initialize()
    store.ingest([], checkpoint=(SOURCE, 10))
    with pytest.raises(ValueError):
        store.ingest([demo_alerts()[0], {}], checkpoint=(SOURCE, 11))
    assert store.collection_offset(SOURCE) == 10
    assert store.events() == []


@pytest.mark.parametrize(("stderr", "expected"), [
    ("FullyQualifiedErrorId: System.UnauthorizedAccessException", "access_denied"),
    ("FullyQualifiedErrorId: NoMatchingLogsFound", "channel_missing"),
    ("Another error", "read_failed"),
])
def test_collection_problem_reports_safe_reason(stderr, expected):
    assert collection_problem(CalledProcessError(1, ["powershell.exe"], stderr=stderr)) == expected
