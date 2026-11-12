"""Which features put real-network flows outside the benchmark's normal envelope?

  python scripts/envelope_audit.py data/processed/cicids2017.parquet data/sensor/<session> [...] \
      --results docs/results/envelope_audit.md

The benign envelope is the 0.5th–99.5th percentile of each feature over the benchmark's benign training
flows (after global dedup and the chronological split). Each captured flow is scored by the frozen
detector; for anomaly-only alerts and for quiet flows we count how many features fall outside the
envelope and which features separate the two groups. Aggregates only: no addresses or flow records.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ids.data import BENIGN, LABEL_COL, dedup_global, temporal_split  # noqa: E402
from ids.scoring import align_columns  # noqa: E402


def envelope(benign: pd.DataFrame, q: float = 0.005) -> tuple[pd.Series, pd.Series]:
    return benign.quantile(q), benign.quantile(1 - q)


def outside(X: pd.DataFrame, lo: pd.Series, hi: pd.Series) -> pd.DataFrame:
    return (X < lo) | (X > hi)


def audit(det, X: pd.DataFrame, lo: pd.Series, hi: pd.Series) -> dict:
    pred = det.predict(X)
    out = det.anomaly(X)[1]
    groups = {"anomaly_only": (pred == BENIGN) & out, "classifier": pred != BENIGN,
              "quiet": (pred == BENIGN) & ~out}
    oor = outside(X, lo, hi)
    res = {}
    for name, mask in groups.items():
        m = np.asarray(mask)
        res[name] = {"flows": int(m.sum()),
                     "features_outside_mean": float(oor[m].sum(axis=1).mean()) if m.any() else None,
                     "feature_rates": oor[m].mean().to_dict() if m.any() else {}}
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("benchmark")
    ap.add_argument("sessions", nargs="+", type=Path)
    ap.add_argument("--model-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--results", default="docs/results/envelope_audit.md")
    args = ap.parse_args()
    t0 = time.perf_counter()
    det = joblib.load(args.model_dir / "detector.joblib")
    f = det.features
    train, _, _ = temporal_split(dedup_global(pd.read_parquet(args.benchmark)))
    lo, hi = envelope(train[train[LABEL_COL] == BENIGN][f])
    frames = []
    for s in args.sessions:
        aligned, missing = align_columns(pd.read_csv(s / "validated.csv", low_memory=False), f)
        if missing:
            raise SystemExit(f"{s.name}: features missing")
        frames.append(aligned[f].apply(pd.to_numeric, errors="coerce"))
    X = pd.concat(frames, ignore_index=True)
    res = audit(det, X, lo, hi)
    a, q = res["anomaly_only"], res["quiet"]
    gap = pd.Series({k: a["feature_rates"].get(k, 0) - q["feature_rates"].get(k, 0) for k in f}).sort_values(ascending=False)
    md = ["# Benign-envelope audit", "",
          f"Generated on {time.strftime('%Y-%m-%d')}. {len(X):,} flows from {len(args.sessions)} sessions, scored by the "
          "frozen detector. The envelope is the 0.5th–99.5th percentile of each feature over benchmark benign "
          "training flows.", "", "| Group | Flows | Mean features outside the envelope |", "|---|---:|---:|"]
    for name, label in [("anomaly_only", "Anomaly-only alerts"), ("classifier", "Classifier alerts"), ("quiet", "No alert")]:
        g = res[name]
        md.append(f"| {label} | {g['flows']} | {'n/a' if g['features_outside_mean'] is None else format(g['features_outside_mean'], '.1f')} |")
    md += ["", "## Features that separate anomaly-only alerts from quiet flows", "",
           "| Feature | Outside envelope: anomaly-only | Outside envelope: quiet |", "|---|---:|---:|"]
    for k in gap.head(12).index:
        md.append(f"| {k} | {a['feature_rates'].get(k, 0):.0%} | {q['feature_rates'].get(k, 0):.0%} |")
    md += ["", "Unlabelled traffic: alerts are candidate false alerts. Accuracy is not reported (rule 4).", ""]
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(md), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps({"sessions": len(args.sessions), "flows": int(len(X)), **res},
                                                   indent=1, default=float), encoding="utf-8")
    print(f"results in {out} ({(time.perf_counter() - t0) / 60:.1f} min)")


if __name__ == "__main__":
    main()
