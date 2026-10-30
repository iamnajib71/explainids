"""Backfill `service_added` in service-aware result files written before it was recorded.

  python scripts/patch_service_added.py docs/results/service_aware.json [...]

The number of service flows actually added is the training-row difference between a service-aware run
and the run with the same k and seed and no service flows. The markdown is regenerated from the JSON.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_aware_eval import to_markdown  # noqa: E402

for path in map(Path, sys.argv[1:]):
    res = json.loads(path.read_text(encoding="utf-8"))
    base = {(r["k"], r["seed"]): r["training_rows"] for r in res["runs"] if r.get("service_flows") == 0}
    for r in res["runs"]:
        if r.get("service_flows") is not None:
            r["service_added"] = r["training_rows"] - base[(r["k"], r["seed"])]
    path.write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    path.with_suffix(".md").write_text(to_markdown(res), encoding="utf-8")
    print(path, sorted({(r["service_flows"], r["service_added"]) for r in res["runs"] if "service_added" in r}))
