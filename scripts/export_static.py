"""Export a server-free build of the console: the web files plus pre-scored replay data.

Usage: python scripts/export_static.py site [--full-app URL] [--chunk 500]

Every replay flow is scored offline by the same code the API runs (model, SHAP, ATT&CK mapping,
ground-truth verdicts), so the static console shows real model output; it simply plays it back.
File upload needs the live API, so the static build links to the full app instead.
"""
import argparse
import json
import shutil
from pathlib import Path

from api import main as appmod

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--full-app", default="", help="URL of the live deployment (shown on the upload page)")
    ap.add_argument("--chunk", type=int, default=500)
    args = ap.parse_args()
    if not 1 <= args.chunk <= 500:  # /replay returns at most 500 flows per call
        ap.error("--chunk must be between 1 and 500")

    out = Path(args.out).resolve()
    if out.exists():
        if not (out / "data" / "health.json").exists():  # only ever replace an earlier export
            ap.error(f"{out} exists and is not a previous static export; choose a new directory")
        shutil.rmtree(out)
    shutil.copytree(ROOT / "web", out)
    data = out / "data"
    (data / "replay").mkdir(parents=True)

    health = appmod.health()
    total = health["replay_flows"]
    chunks = 0
    for cursor in range(0, total, args.chunk):
        batch = appmod.replay(cursor=cursor, n=min(args.chunk, total - cursor))
        (data / "replay" / f"{chunks:03d}.json").write_text(json.dumps(batch, default=str, separators=(",", ":")))
        chunks += 1
        print(f"scored flows {cursor:,}-{cursor + len(batch['flows']) - 1:,}", flush=True)

    (data / "model.json").write_text(json.dumps(appmod.model_card(), default=str))
    (data / "health.json").write_text(json.dumps({**health, "chunk": args.chunk, "chunks": chunks}))
    (out / "sample.csv").write_text(appmod.sample_csv(rows=3000).body.decode())

    config = {"data": "data/", "fullApp": args.full_app}
    page = (out / "index.html").read_text(encoding="utf-8")
    page = page.replace('<script src="app.js"></script>',
                        f"<script>window.EXPLAINIDS_STATIC = {json.dumps(config)};</script>\n"
                        '<script src="app.js"></script>')
    (out / "index.html").write_text(page, encoding="utf-8")
    (out / ".nojekyll").write_text("")
    print(f"static site: {out} ({chunks} replay chunks, {total:,} flows)")


if __name__ == "__main__":
    main()
