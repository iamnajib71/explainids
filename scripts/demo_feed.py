"""Stream saved, validated flows into a running local console, for a rehearsed live demo.

  python scripts/demo_feed.py --url http://127.0.0.1:8000/sensor/ingest $(cat data/study_sessions_day2.txt)
  python scripts/demo_feed.py --url http://127.0.0.1:8001/sensor/ingest data/lab/run_20261025T050628Z/flows_labelled.csv

Arguments are sensor session folders (their `validated.csv` is sent) or flow CSVs (validated first; labels are
stripped). Loopback only, like the sensor itself; the key, if the console has one, is read from the environment.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ids import sensor  # noqa: E402


def validated(path: Path, features: list[str], work: Path) -> Path:
    if path.is_dir():
        return path / "validated.csv"
    out = work / f"{path.parent.name}_{path.stem}.csv"
    sensor.validate_csv(path, out, features)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+", type=Path)
    ap.add_argument("--url", default="http://127.0.0.1:8000/sensor/ingest")
    ap.add_argument("--model-card", type=Path, default=ROOT / "models/model_card.json")
    ap.add_argument("--api-key-env", default="EXPLAINIDS_API_KEY")
    ap.add_argument("--session", default="demo", help="sensor session token shown in the console")
    ap.add_argument("--pause", type=float, default=0.5, help="seconds between batches, so the queue visibly fills")
    args = ap.parse_args(argv)
    features = sensor.load_features(args.model_card)
    key = os.environ.get(args.api_key_env) or "open-local-console"  # a keyless local console accepts any key
    sent = 0
    with tempfile.TemporaryDirectory() as tmp:
        for n, src in enumerate(args.sources):
            for i, (count, payload) in enumerate(sensor.csv_batches(validated(src, features, Path(tmp)))):
                sensor.push_batch(args.url, key, payload, args.session, f"s{n:03d}b{i:04d}", None)
                sent += count
                time.sleep(args.pause)
    print(f"sent {sent} flows from {len(args.sources)} sources to {args.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
