"""Repair the deployed detector for this site from analyst triage and the site's own normal traffic.

  python scripts/repair_model.py data/processed/cicids2017.parquet --repair-set repair_set.csv \
      --local-sessions data/sensor/<session> [...] --outdir data/models_repaired

The two local repairs measured in docs/RESEARCH.md, applied to the model the console serves:

  1. Classifier: retrain on the original training split plus the analyst's dismissed alerts
     (GET /triage/repair-set.csv), labelled benign.
  2. Anomaly layer: attach the site's normal traffic as an exemplar envelope (ids.envelope.LocalNormal),
     so a benchmark anomaly alert stands only if the flow is also unlike every local normal flow.

Before and after are reported on the benchmark test split (macro F1, attack recall, benign FPR) and on the
local sessions (alert rate), so a gain on one cannot hide a loss on the other. Serve the result with
EXPLAINIDS_MODEL_DIR=<outdir>. Local sessions are treated as normal traffic: pass only captures from a
period the site believes was attack-free.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ids.data import BENIGN, LABEL_COL, stratified_sample, temporal_split  # noqa: E402
from ids.envelope import LocalNormal  # noqa: E402
from ids.evaluate import report  # noqa: E402
from ids.models import Detector  # noqa: E402
from ids.scoring import align_columns  # noqa: E402


def load_local(sessions: list[Path], feats: list[str]) -> pd.DataFrame:
    frames = []
    for s in sessions:
        aligned, missing = align_columns(pd.read_csv(s / "validated.csv", low_memory=False), feats)
        if missing:
            raise SystemExit(f"{s.name}: {len(missing)} features missing")
        X = aligned[feats].apply(pd.to_numeric, errors="coerce")
        frames.append(X[np.isfinite(X.to_numpy(dtype=float)).all(axis=1)])
    return pd.concat(frames, ignore_index=True)


def load_repair(path: Path, feats: list[str]) -> pd.DataFrame:
    raw = pd.read_csv(path)
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise SystemExit(f"repair set lacks {len(missing)} model features, e.g. {missing[:3]}")
    X = aligned[feats].apply(pd.to_numeric, errors="coerce")
    X = X[np.isfinite(X.to_numpy(dtype=float)).all(axis=1)].copy()
    X[LABEL_COL] = BENIGN
    return X


def summary(det, test: pd.DataFrame, local: pd.DataFrame, feats: list[str]) -> dict:
    y = test[LABEL_COL]
    pred = det.predict(test[feats])
    rep = report(y, pred, det.classes)
    attacks = y != BENIGN
    flagged_local = (det.predict(local) != BENIGN) | det.anomaly(local)[1]
    return {"macro_f1": float(rep["macro"]["f1"]), "benign_fpr": float(rep["benign_fpr"]),
            "attack_recall": float((pred[attacks.to_numpy()] != BENIGN).mean()),
            "local_flows": int(len(local)), "local_alerts": int(flagged_local.sum()),
            "local_alert_rate": float(flagged_local.mean())}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parquet", help="the benchmark the deployed model was trained on")
    ap.add_argument("--model-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--repair-set", type=Path, help="CSV from GET /triage/repair-set.csv")
    ap.add_argument("--local-sessions", nargs="+", type=Path, required=True)
    ap.add_argument("--budget", type=float, default=0.01, help="share of local normal traffic allowed to look unusual")
    ap.add_argument("--outdir", type=Path, default=ROOT / "data/models_repaired")
    args = ap.parse_args()

    t0 = time.perf_counter()
    base = joblib.load(args.model_dir / "detector.joblib")
    card = json.loads((args.model_dir / "model_card.json").read_text(encoding="utf-8"))
    feats = base.features
    cap = card.get("split", {}).get("train_cap_per_class", 60000)
    train, val, test = temporal_split(pd.read_parquet(args.parquet))
    train = stratified_sample(train, cap)
    local = load_local(args.local_sessions, feats)
    repair = load_repair(args.repair_set, feats) if args.repair_set else None

    before = summary(base, test, local, feats)
    parts = [train[feats + [LABEL_COL]]] + ([repair[feats + [LABEL_COL]]] if repair is not None and len(repair) else [])
    fitted = pd.concat(parts, ignore_index=True)
    det = Detector(base.name, anomaly_log=getattr(base, "anomaly_log", False)).fit(fitted[feats], fitted[LABEL_COL])
    det.fit_anomaly(fitted[fitted[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(val[val[LABEL_COL] == BENIGN][feats])
    det.local_normal = LocalNormal(feats, local, args.budget)
    after = summary(det, test, local, feats)
    # The local sessions trained the envelope, so their after-rate is optimistic; report it as such.

    args.outdir.mkdir(parents=True, exist_ok=True)
    joblib.dump(det, args.outdir / "detector.joblib")
    for extra in ("replay.parquet",):
        if (args.model_dir / extra).exists():
            shutil.copy2(args.model_dir / extra, args.outdir / extra)
    card["repair"] = {"generated": time.strftime("%Y-%m-%d"), "repair_flows": 0 if repair is None else int(len(repair)),
                      "local_sessions": len(args.local_sessions), "local_normal_flows": int(len(local)),
                      "envelope_budget": args.budget, "before": before, "after": after,
                      "note": "after-rate on local sessions is in-sample for the envelope"}
    (args.outdir / "model_card.json").write_text(json.dumps(card, indent=1), encoding="utf-8")
    print(json.dumps({"before": before, "after": after, "minutes": round((time.perf_counter() - t0) / 60, 1)}, indent=1))


if __name__ == "__main__":
    main()
