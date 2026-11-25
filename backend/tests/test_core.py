import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from north import Store, build_cases, normalize, report


class IncidentTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.store = Store(path=Path(folder.name) / "test.sqlite3")
        self.store.initialize()
        self.alerts = json.loads(
            (Path(__file__).parents[1] / "fixtures" / "demo.json").read_text(encoding="utf-8")
        )

    def test_fixture_replay_is_idempotent_and_evidence_is_linked(self):
        self.assertEqual(self.store.ingest(self.alerts[::-1]), 3)
        self.assertEqual(self.store.ingest(self.alerts), 0)
        case, = build_cases(self.store.events())
        self.assertEqual([item["kind"] for item in case["evidence"]], [1, 3, 11])
        self.assertEqual(case["links"][0]["evidence_id"], case["evidence"][1]["id"])
        for item in case["evidence"]:
            self.assertIn(item["id"], report(case))

    def test_near_misses(self):
        for key, value in (
            ("targetFilename", "note.txt"),
            ("processGuid", "{different-process}"),
        ):
            with self.subTest(key=key):
                alerts = deepcopy(self.alerts)
                alerts[2]["data"]["win"]["eventdata"][key] = value
                self.assertEqual(build_cases([normalize(alert) for alert in alerts]), [])
        alerts = deepcopy(self.alerts)
        alerts[2]["data"]["win"]["system"]["systemTime"] = "2026-01-15T10:30:00Z"
        self.assertEqual(build_cases([normalize(alert) for alert in alerts]), [])

    def test_malformed_batch_is_atomic(self):
        with self.assertRaises(ValueError):
            self.store.ingest([self.alerts[0], {}])
        self.assertEqual(self.store.events(), [])
