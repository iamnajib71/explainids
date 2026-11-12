"""SHAP stability across training seeds (RQ2), with fixed training and test flows.

Usage:
  python scripts/shap_stability_eval.py data/processed/cicids2017.parquet --model lgbm --cap 60000 \
      --seeds 42,1,2,3,4 --flows 500 --k 5 --results docs/results/shap_stability_cicids2017.md

Globally deduplicate, split chronologically per class (70/10/20), then cap training
rows per class with seed 42. Select a proportional stratified sample of --flows
attack flows TOTAL from the test split, also at seed 42, once for every model.
Only the model training seed varies. Set random_state before Detector.fit;
LightGBM additionally needs bagging_fraction=0.8, bagging_freq=1 and
feature_fraction=0.8: without stochastic sampling it is deterministic and changing
the seed alone yields identical SHAP values. RF/XGBoost otherwise keep defaults.

Local comparisons use each model's predicted-class SHAP top-k, and exclude/count
flow/seed pairs with different predictions (including benign/attack disagreements).
Global importance uses those same fixed attack flows, summed across classes by
ids.explain.global_importance: top-10 Jaccard and Spearman over the union of the
top-15 lists, with missing rank 16. Identical nonempty rankings have correlation 1;
other undefined correlations are reported as null/n/a. Performance is evaluated
on the FULL test split, including benign flows. No anomaly model is fitted.
"""
from __future__ import annotations

import argparse
import json
import time
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from ids.data import BENIGN, LABEL_COL, dedup_global, feature_columns, stratified_sample, temporal_split
from ids.evaluate import report
from ids.explain import Explainer, global_importance, rank_agreement
from ids.models import Detector

DATA_SEED = 42
LGBM_SAMPLING = {"bagging_fraction": 0.8, "bagging_freq": 1, "feature_fraction": 0.8}


def attack_sample(test: pd.DataFrame, flows: int) -> pd.DataFrame:
    """Sample up to flows total attack rows, using proportional largest remainders."""
    if flows < 1:
        raise ValueError("flows must be positive")
    attacks = test[test[LABEL_COL] != BENIGN]
    if attacks.empty:
        raise ValueError("the test split contains no attack flows to explain")
    sizes = attacks.groupby(LABEL_COL, sort=True).size()
    quotas = sizes * (min(flows, len(attacks)) / len(attacks))
    counts = np.floor(quotas).astype(int)
    remaining = min(flows, len(attacks)) - int(counts.sum())
    extra = (quotas - counts).sort_values(ascending=False, kind="stable").head(remaining).index
    counts.loc[extra] += 1
    parts = [group.sample(int(counts[label]), random_state=DATA_SEED)
             for label, group in attacks.groupby(LABEL_COL, sort=True)]
    # Preserve original row indices in the result metadata for reproducibility.
    return pd.concat(parts).sample(frac=1, random_state=DATA_SEED)


def fit(train: pd.DataFrame, feats: list[str], model: str, seed: int) -> Detector:
    det = Detector(model)
    params = {"random_state": seed}
    if model == "lgbm":
        params.update(LGBM_SAMPLING)
    det.model.set_params(**params)
    return det.fit(train[feats], train[LABEL_COL])


def explain_run(det: Detector, test: pd.DataFrame, explained: pd.DataFrame, seed: int, k: int) -> dict:
    """Capture reusable per-seed outputs; score performance on all test classes."""
    X = explained[det.features]
    predicted = list(det.predict(X))
    top = Explainer(det).top_features(X, predicted, k=k)
    metrics = report(test[LABEL_COL], det.predict(test[det.features]))
    return {"seed": seed, "predicted": predicted,
            "local_top": [[item["feature"] for item in row] for row in top],
            "global_top": global_importance(det, X, n=len(X), k=15),
            "performance": {"macro": metrics["macro"], "benign_fpr": metrics["benign_fpr"],
                            "per_class": metrics["per_class"].to_dict(orient="index"),
                            "confusion": metrics["confusion"].to_dict(orient="index")}}


def summary(values: list[float]) -> dict:
    return {"count": len(values), "median": float(np.median(values)) if values else None,
            "p10": float(np.quantile(values, 0.1)) if values else None}


def global_spearman(a: list[str], b: list[str]) -> float | None:
    """Compare top-15 rankings, assigning rank 16 to features missing from a list."""
    features = sorted(set(a) | set(b))
    if not features:
        return None
    ra = {feature: i + 1 for i, feature in enumerate(a)}
    rb = {feature: i + 1 for i, feature in enumerate(b)}
    x, y = [ra.get(f, 16) for f in features], [rb.get(f, 16) for f in features]
    if x == y:
        return 1.0
    if len(set(x)) < 2 or len(set(y)) < 2:
        return None
    return float(spearmanr(x, y).statistic)


def compare_runs(runs: list[dict]) -> dict:
    """Pool flow/pair observations only when both predicted labels agree."""
    if len(runs) < 2:
        raise ValueError("at least two seed runs are required")
    n = len(runs[0]["predicted"])
    if any(len(r["predicted"]) != n or len(r["local_top"]) != n for r in runs):
        raise ValueError("all runs must explain the same number of flows")
    local = []
    by_class: dict[str, list[float]] = {c: [] for r in runs for c in r["predicted"]}
    pairs = []
    skipped = 0
    for (i, a), (j, b) in combinations(enumerate(runs), 2):
        values = []
        different = 0
        for pa, pb, ta, tb in zip(a["predicted"], b["predicted"], a["local_top"], b["local_top"], strict=True):
            if pa != pb:
                different += 1
                continue
            overlap = rank_agreement(ta, tb)
            values.append(overlap)
            by_class[pa].append(overlap)
        local.extend(values)
        skipped += different
        ga = [f["feature"] for f in a["global_top"]]
        gb = [f["feature"] for f in b["global_top"]]
        pairs.append({"run_a": i, "run_b": j, "seed_a": a["seed"], "seed_b": b["seed"],
                      "local": summary(values), "skipped_prediction_changes": different,
                      "global_top10_jaccard": rank_agreement(ga[:10], gb[:10]),
                      "global_spearman": global_spearman(ga, gb)})
    return {"local": {"overall": summary(local),
                      "per_predicted_class": {c: summary(v) for c, v in sorted(by_class.items())},
                      "total_pairs": n * len(pairs), "skipped_prediction_changes": skipped},
            "pairs": pairs}


def fmt(value: float | None) -> str:
    return "n/a" if value is None or not np.isfinite(value) else f"{value:.4f}"


def to_markdown(res: dict, cmd: str) -> str:
    md = [f"# SHAP stability: {res['dataset']}", "", f"Generated by `{cmd}` on {res['generated']}.", "",
          f"Model: **{res['model']}**. Training cap: {res['cap']:,} per class; "
          f"{res['train_rows']:,} training rows, {res['test_rows']:,} full test rows. "
          f"Globally deduplicated, then chronologically split per class (70/10/20). Training rows and the "
          f"{res['explained_flows']:,} explained test attack flows are fixed at seed 42; only training seeds vary.", "",
          "LightGBM uses bagging_fraction=0.8, bagging_freq=1, feature_fraction=0.8, plus random_state "
          "per seed. Without stochastic sampling LightGBM is deterministic: varying only the seed gives "
          "identical SHAP values. RF/XGBoost use their existing defaults plus random_state.", "",
          f"Local comparisons use predicted-class top-{res['k']} SHAP features. Only matching predictions "
          "are compared, including matching BENIGN predictions on true attack flows. Summaries pool "
          "flow/seed-pair observations, not independent flows or per-seed averages.", "",
          f"Skipped prediction disagreements: **{res['local']['skipped_prediction_changes']:,}** of "
          f"{res['local']['total_pairs']:,} candidate flow/seed pairs. Conditional stability must be read "
          "alongside this count and full-test performance.", "",
          "## Local stability", "", "| Predicted class | Compared pairs | Median Jaccard | 10th percentile |",
          "|---|---:|---:|---:|"]
    for label, s in [("Overall", res["local"]["overall"]), *res["local"]["per_predicted_class"].items()]:
        md.append(f"| {label} | {s['count']:,} | {fmt(s['median'])} | {fmt(s['p10'])} |")
    md += ["", "## Pairwise global stability", "",
           "Global mean absolute SHAP uses the same explained attack flows for every seed, summed across "
           "classes by ids.explain.global_importance. Jaccard compares the top 10; Spearman uses the "
           "union of the top 15, with missing rank 16. With fewer features, all available features are "
           "used. Identical nonempty rankings have correlation 1; other undefined statistics are n/a.", "",
           "| Run/seed A | Run/seed B | Local pairs | Prediction changes skipped | Top-10 Jaccard | Spearman |",
           "|---|---|---:|---:|---:|---:|"]
    for p in res["pairs"]:
        md.append(f"| {p['run_a']}/{p['seed_a']} | {p['run_b']}/{p['seed_b']} | {p['local']['count']} | "
                  f"{p['skipped_prediction_changes']} | {fmt(p['global_top10_jaccard'])} | {fmt(p['global_spearman'])} |")
    md += ["", "## Full-test performance", "",
           "| Run | Seed | Macro precision | Macro recall | Macro F1 | Benign FPR |",
           "|---|---|---:|---:|---:|---:|"]
    for i, run in enumerate(res["runs"]):
        p = run["performance"]
        md.append(f"| {i} | {run['seed']} | {fmt(p['macro']['precision'])} | {fmt(p['macro']['recall'])} | "
                  f"{fmt(p['macro']['f1'])} | {fmt(p['benign_fpr'])} |")
    for i, run in enumerate(res["runs"]):
        p = run["performance"]
        md += ["", f"### Run {i}, seed {run['seed']}", "",
               "| Class | Precision | Recall | F1 | Support |", "|---|---:|---:|---:|---:|"]
        md += [f"| {c} | {fmt(v['precision'])} | {fmt(v['recall'])} | {fmt(v['f1'])} | {int(v['support'])} |"
               for c, v in p["per_class"].items()]
        labels = list(p["confusion"])
        md += ["", "Confusion matrix (rows true, columns predicted):", "",
               "| True / predicted | " + " | ".join(labels) + " |",
               "|---|" + "---:|" * len(labels)]
        md += [f"| {c} | " + " | ".join(str(int(p["confusion"][c][d])) for d in labels) + " |" for c in labels]
        md += ["", "Global top-15: " + ", ".join(f["feature"] for f in run["global_top"]) + "."]
    md += ["", f"Total run time {res['minutes']:.2f} min."]
    return "\n".join(md) + "\n"


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def seeds(value: str) -> list[int]:
    try:
        values = [int(s.strip()) for s in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from exc
    if len(values) < 2 or any(s < 0 or s >= 2**32 for s in values):
        raise argparse.ArgumentTypeError("provide at least two seeds in [0, 2**32); repeats are allowed")
    return values


def json_safe(value):
    """Use JSON null for undefined metrics, including an absent benign test class."""
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, float) and not np.isfinite(value):
        return None
    return value


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("parquet")
    ap.add_argument("--model", choices=["lgbm", "xgb", "rf"], default="lgbm")
    ap.add_argument("--cap", type=positive, default=60000)
    ap.add_argument("--seeds", type=seeds, default=seeds("42,1,2,3,4"))
    ap.add_argument("--flows", type=positive, default=500, help="total test attack flows to explain")
    ap.add_argument("--k", type=positive, default=5)
    ap.add_argument("--results", default="docs/results/shap_stability.md")
    args = ap.parse_args()

    t0 = time.perf_counter()
    df = dedup_global(pd.read_parquet(args.parquet))
    train, _, test = temporal_split(df)
    if train.empty or test.empty:
        ap.error("chronological split requires nonempty training and test data")
    train = stratified_sample(train, args.cap, seed=DATA_SEED)
    feats = feature_columns(df)
    try:
        explained = attack_sample(test, args.flows)
    except ValueError as exc:
        ap.error(str(exc))
    runs = []
    for seed in args.seeds:
        det = fit(train, feats, args.model, seed)
        run = explain_run(det, test, explained, seed, args.k)
        runs.append(run)
        print(f"seed {seed}: macro F1 {fmt(run['performance']['macro']['f1'])}, "
              f"benign FPR {fmt(run['performance']['benign_fpr'])}", flush=True)
    res = {"dataset": Path(args.parquet).stem, "generated": time.strftime("%Y-%m-%d"),
           "model": args.model, "cap": args.cap, "seeds": args.seeds, "data_seed": DATA_SEED,
           "lgbm_sampling": LGBM_SAMPLING if args.model == "lgbm" else None,
           "requested_flows": args.flows, "explained_flows": len(explained), "k": args.k,
           "features": feats, "train_rows": len(train), "test_rows": len(test),
           "explained_test_indices": [int(i) for i in explained.index],
           "explained_class_counts": {str(c): int(n) for c, n in explained[LABEL_COL].value_counts().items()},
           "runs": runs, **compare_runs(runs), "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results).with_suffix(".md")
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = (f'python scripts/shap_stability_eval.py "{args.parquet}" --model {args.model} --cap {args.cap} '
           f'--seeds {",".join(map(str, args.seeds))} --flows {args.flows} --k {args.k} --results "{out}"')
    out.write_text(to_markdown(res, cmd), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(json_safe(res), indent=1, allow_nan=False), encoding="utf-8")
    print(f"results in {out} and {out.with_suffix('.json')}")


if __name__ == "__main__":
    main()
