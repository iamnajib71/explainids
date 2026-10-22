"""Train and compare ExplainIDS detectors on a processed Parquet dataset; export app artefacts.

Usage:
  python scripts/train_baseline.py data/processed/cicids2017.parquet --models lgbm,xgb,rf \
      --cap 60000 --results docs/results/cicids2017_baseline.md

Chronological per-class split (ids.data.temporal_split), class weighting, benign-only Isolation
Forest with a validation-tuned threshold. The best model on *validation* macro F1 is kept; all are
reported on the held-out test split. Accuracy is never reported alone (rule 4).

Outputs (models/ is gitignored):
  models/detector.joblib      best detector
  models/model_card.json      metrics, confusion matrices, global SHAP importance (read by the app)
  models/replay.parquet       real held-out test flows with ground truth, replayed by the app
"""
import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ids import SEED
from ids.data import BENIGN, LABEL_COL, feature_columns, stratified_sample, temporal_split
from ids.evaluate import binary_pr_auc, latency_ms_per_flow, report
from ids.explain import Explainer
from ids.models import Detector

REPLAY_META = ["Src IP", "Dst IP", "Src Port", "Timestamp"]


def evaluate(det: Detector, X: pd.DataFrame, y: pd.Series) -> dict:
    pred = det.predict(X)
    rep = report(y, pred, det.classes)
    proba = det.predict_proba(X)
    return {"rep": rep, "pr_auc": binary_pr_auc(y, 1 - proba[:, det.benign_index]),
            "latency_ms": latency_ms_per_flow(det.predict, X.head(5000))}


def global_importance(det: Detector, X: pd.DataFrame, n: int = 2000, k: int = 15) -> list[dict]:
    """Mean |SHAP| per feature over a test sample, summed across classes."""
    sample = X.sample(min(n, len(X)), random_state=SEED)
    values = Explainer(det)._explainer.shap_values(sample[det.features])
    arr = np.abs(np.stack(values, axis=-1) if isinstance(values, list) else np.asarray(values))
    imp = arr.mean(axis=0).sum(axis=-1) if arr.ndim == 3 else arr.mean(axis=0)
    top = np.argsort(-imp)[:k]
    return [{"feature": det.features[j], "importance": float(imp[j])} for j in top]


def replay_set(test: pd.DataFrame, per_attack: int = 400, benign: int = 6000) -> pd.DataFrame:
    """A time-ordered, attack-enriched sample of real test flows for the live replay."""
    parts = [g.sample(min(len(g), benign if label == BENIGN else per_attack), random_state=SEED)
             for label, g in test.groupby(LABEL_COL)]
    out = pd.concat(parts)
    out["Timestamp"] = pd.to_datetime(out["Timestamp"], format="mixed")
    return out.sort_values("Timestamp").reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("parquet")
    ap.add_argument("--models", default="lgbm,xgb,rf")
    ap.add_argument("--cap", type=int, default=60000, help="max training rows per class (memory guard)")
    ap.add_argument("--outdir", default="models")
    ap.add_argument("--results", default="docs/results/baseline.md")
    args = ap.parse_args()

    t0 = time.perf_counter()
    df = pd.read_parquet(args.parquet)
    feats = feature_columns(df)
    train, val, test = temporal_split(df)
    train = stratified_sample(train, args.cap)
    print(f"loaded {len(df):,} rows, {len(feats)} features | train={len(train):,} val={len(val):,} "
          f"test={len(test):,}", flush=True)

    results, best = {}, None
    for name in args.models.split(","):
        t = time.perf_counter()
        det = Detector(name).fit(train[feats], train[LABEL_COL])
        val_f1 = report(val[LABEL_COL], det.predict(val[feats]), det.classes)["macro"]["f1"]
        ev = evaluate(det, test[feats], test[LABEL_COL])
        ev.update(val_macro_f1=val_f1, train_s=time.perf_counter() - t)
        results[name] = ev
        print(f"{name}: val F1 {val_f1:.3f} | test F1 {ev['rep']['macro']['f1']:.3f} | "
              f"FPR {ev['rep']['benign_fpr']:.4f} | {ev['train_s']:.0f}s", flush=True)
        if best is None or val_f1 > results[best[0]]["val_macro_f1"]:
            best = (name, det)

    name, det = best
    det.fit_anomaly(train[train[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(val[val[LABEL_COL] == BENIGN][feats])
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(det, out / "detector.joblib")
    replay_set(test)[[c for c in REPLAY_META if c in test] + feats + [LABEL_COL]].to_parquet(out / "replay.parquet")

    dataset = Path(args.parquet).stem
    card = {
        "dataset": dataset, "generated": time.strftime("%Y-%m-%d"), "selected_model": name,
        "split": {"method": "chronological per class (70/10/20)", "train": len(train), "val": len(val),
                  "test": len(test), "train_cap_per_class": args.cap},
        "features": feats, "classes": det.classes,
        "test_class_counts": test[LABEL_COL].value_counts().to_dict(),
        "models": {m: {"val_macro_f1": r["val_macro_f1"], "train_seconds": r["train_s"],
                       "macro": r["rep"]["macro"], "benign_fpr": r["rep"]["benign_fpr"],
                       "pr_auc": r["pr_auc"], "latency_ms": r["latency_ms"],
                       "per_class": r["rep"]["per_class"].reset_index(names="class").to_dict("records"),
                       "confusion": r["rep"]["confusion"].values.tolist()}
                   for m, r in results.items()},
        "global_importance": global_importance(det, test[feats]),
        "anomaly_threshold": det.anomaly_threshold,
    }
    (out / "model_card.json").write_text(json.dumps(card, indent=1), encoding="utf-8")

    md = [f"# Baseline results: {dataset}", "",
          f"Generated by `python scripts/train_baseline.py {args.parquet} --models {args.models} --cap {args.cap}` "
          f"on {card['generated']}. Split: {card['split']['method']}; train {len(train):,} (capped "
          f"{args.cap:,}/class), val {len(val):,}, test {len(test):,} flows. Selected on validation macro F1: "
          f"**{name.upper()}**.", "", "| Model | Val macro F1 | Test macro P | Test macro R | Test macro F1 | "
          "Benign FPR | Attack PR-AUC | Latency ms/flow |", "|---|---|---|---|---|---|---|---|"]
    for m, r in results.items():
        mac = r["rep"]["macro"]
        md.append(f"| {m.upper()} | {r['val_macro_f1']:.3f} | {mac['precision']:.3f} | {mac['recall']:.3f} | "
                  f"{mac['f1']:.3f} | {r['rep']['benign_fpr']:.4f} | {r['pr_auc']:.3f} | {r['latency_ms']:.4f} |")
    rep = results[name]["rep"]
    md += ["", f"## {name.upper()}: per-class precision / recall / F1 (test)", "",
           rep["per_class"].round(3).to_markdown(), "", "## Confusion matrix (rows = true, cols = predicted)", "",
           rep["confusion"].to_markdown(), "", f"Total run time {(time.perf_counter() - t0) / 60:.1f} min."]
    Path(args.results).parent.mkdir(parents=True, exist_ok=True)
    Path(args.results).write_text("\n".join(md), encoding="utf-8")
    print(f"selected {name}; artefacts in {out}/, results in {args.results}")


if __name__ == "__main__":
    main()
