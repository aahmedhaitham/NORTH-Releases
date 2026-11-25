"""Compare two installed Ollama models on the NORTH draft endpoint."""

import json
import os
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from fastapi.testclient import TestClient

from main import make_app
from north import Store


MODELS = ("qwen2.5-coder:7b", "huihui_ai/qwen3-abliterated:8b-v2")
REPEATS = 3


def compare():
    fixture = Path(__file__).with_name("fixtures") / "demo.json"
    alerts = json.loads(fixture.read_text(encoding="utf-8"))
    no_network = [
        alert for alert in alerts
        if int(alert["data"]["win"]["system"]["eventID"]) != 3
    ]
    os.environ["NORTH_SEED_DEMO"] = "0"
    with TemporaryDirectory() as folder:
        for model in MODELS:
            os.environ["OLLAMA_MODEL"] = model
            print(f"\n{model}", flush=True)
            times, valid, file_first = [], 0, 0
            warmed_up = False
            for name, records in (("full", alerts), ("missing-network", no_network)):
                store = Store(path=Path(folder) / f"{name}.sqlite3")
                store.initialize()
                store.ingest(records)
                with TestClient(make_app(store)) as client:
                    case, = client.get("/api/cases").json()
                    url = f"/api/cases/{case['id']}/draft"
                    file_id = next(event["id"] for event in case["evidence"] if event["kind"] == 11)
                    if not warmed_up:
                        start = perf_counter()
                        response = client.post(url)
                        print(f"  Warm-up: HTTP {response.status_code}, {perf_counter() - start:.2f} s", flush=True)
                        if response.status_code == 503:
                            print(f"  {response.json()['detail']}", flush=True)
                            break
                        warmed_up = True

                    for run in range(1, REPEATS + 1):
                        start = perf_counter()
                        response = client.post(url)
                        elapsed = perf_counter() - start
                        if response.is_success:
                            claims = response.json()["claims"]
                            valid += 1
                            first = file_id in claims[0]["evidence_ids"]
                            file_first += first
                            times.append(elapsed)
                            result = "file creation first" if first else "another observation first"
                        else:
                            result = response.json()["detail"]
                        print(f"  {name} #{run}: {elapsed:.2f} s, HTTP {response.status_code}, {result}", flush=True)

            if warmed_up:
                latency = f"{median(times):.2f} s" if times else "unavailable"
                print(
                    f"  Warm median for valid drafts: {latency}. "
                    f"Valid: {valid}/{2 * REPEATS}. File creation first: {file_first}/{valid}.",
                    flush=True,
                )


if __name__ == "__main__":
    import argparse

    argparse.ArgumentParser(description=__doc__).parse_args()
    compare()
