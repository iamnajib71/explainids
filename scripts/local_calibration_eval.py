"""Local calibration: can a detector trained on one network be adapted to a new one using only a short
sample of the new network's normal traffic?

Usage:
  python scripts/local_calibration_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --sizes 1000,5000,20000 --seeds 42,1,2 --target-fpr 0.01 --results docs/results/local_calibration.md

Scenario: an SME installs a model trained elsewhere and lets it watch its own network before alerting.
Only BENIGN flows from the earliest part of the target capture (its chronological training split) are
used, with no attack labels, as a real site would have none. Everything is scored on the target's later
test split. Each calibration sample is split 70/30: the 70% fits a local Isolation Forest, and the 30%
sets every threshold, so no rule is tuned on the flows it is scored on.

Alert rules, each held to the same false-alarm budget (--target-fpr) on the local hold-out:
  as deployed      classifier says attack, or the source-trained Isolation Forest flags the flow
  local anomaly    classifier says attack, or an Isolation Forest refit on local benign flows (signed-log)
  local threshold  P(benign) below a threshold chosen so target_fpr of local benign flows alert
  both             local threshold (budget/2) or local anomaly (budget/2)
Reference: a model trained on the target network itself (the in-domain ceiling).

For speed the target test split keeps at most --test-cap flows per class (seed 42). Recall is reported
flow-weighted and class-balanced (mean of per-class detection), with 95% Wilson intervals.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ids import SEED
from ids.data import BENIGN, LABEL_COL, dedup_global, feature_columns, stratified_sample, temporal_split
from ids.evaluate import binary_report
from ids.models import Detector, signed_log

RULES = ["as deployed", "local anomaly", "local threshold", "both"]


def load(path: str, cap: int, test_cap: int) -> dict:
    df = dedup_global(pd.read_parquet(path))
    train, val, test = temporal_split(df)
    return {"name": Path(path).stem, "train": stratified_sample(train, cap), "val": val,
            "test": stratified_sample(test, test_cap), "test_full_rows": len(test)}


def fit_detector(data: dict, feats: list[str], model: str) -> Detector:
    tr, va = data["train"], data["val"]
    det = Detector(model).fit(tr[feats], tr[LABEL_COL])
    det.fit_anomaly(tr[tr[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(va[va[LABEL_COL] == BENIGN][feats])
    return det


def summarise(y: pd.Series, flagged: np.ndarray) -> dict:
    """Alert quality plus class-balanced detection (each attack class counts once)."""
    rep = binary_report(y, flagged)
    per_class = pd.Series(flagged, index=y.index).groupby(y).mean()
    attacks = per_class.drop(BENIGN, errors="ignore")
    return {**rep, "macro_detection": float(attacks.mean()), "per_class": attacks.round(4).to_dict(),
            "false_alarms_per_10k": 1e4 * rep["fpr"]}


def calibrate(det: Detector, local: pd.DataFrame, feats: list[str], budget: float, seed: int) -> dict:
    """Fit a local Isolation Forest on 70% of the benign sample; set all thresholds on the other 30%."""
    hold = local.sample(frac=0.3, random_state=seed)
    fit_part = local.drop(hold.index)
    iforest = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(signed_log(fit_part[feats]))
    if_hold = iforest.score_samples(signed_log(hold[feats]))
    pb_hold = det.predict_proba(hold[feats])[:, det.benign_index]
    return {"iforest": iforest,
            "if_full": float(np.quantile(if_hold, budget)), "if_half": float(np.quantile(if_hold, budget / 2)),
            "pb_full": float(np.quantile(pb_hold, budget)), "pb_half": float(np.quantile(pb_hold, budget / 2))}


def run_direction(src: dict, tgt: dict, feats: list[str], args) -> dict:
    det = fit_detector(src, feats, args.model)
    X, y = tgt["test"][feats], tgt["test"][LABEL_COL]
    pred, pb = det.predict(X), det.predict_proba(X)[:, det.benign_index]
    clf = pred != BENIGN
    deployed = summarise(y, clf | det.anomaly(X)[1])
    ceiling_det = fit_detector(tgt, feats, args.model)
    ceiling = summarise(y, (ceiling_det.predict(X) != BENIGN) | ceiling_det.anomaly(X)[1])
    pool = tgt["train"][tgt["train"][LABEL_COL] == BENIGN]
    rows = []
    for size in args.sizes:
        for seed in args.seeds:
            local = pool.sample(min(size, len(pool)), random_state=seed)
            cal = calibrate(det, local, feats, args.target_fpr, seed)
            scores = cal["iforest"].score_samples(signed_log(X))
            flagged = {"local anomaly": clf | (scores < cal["if_full"]),
                       "local threshold": pb < cal["pb_full"],
                       "both": (pb < cal["pb_half"]) | (scores < cal["if_half"])}
            for rule, f in flagged.items():
                rows.append({"size": size, "seed": seed, "rule": rule, **summarise(y, f)})
            print(f"  {src['name']}->{tgt['name']} size {size} seed {seed}: " + " | ".join(
                f"{r['rule']} R {r['recall']:.3f} FPR {r['fpr']:.4f}" for r in rows[-3:]), flush=True)
    return {"source": src["name"], "target": tgt["name"], "test_flows": len(y), "test_full_rows": tgt["test_full_rows"],
            "deployed": deployed, "ceiling": ceiling, "runs": rows}


def table(res: dict) -> list[str]:
    runs = pd.DataFrame(res["runs"])
    md = [f"### {res['source']} → {res['target']}", "",
          f"Test flows scored: {res['test_flows']:,} (per-class cap; full test split {res['test_full_rows']:,}).", "",
          "| Rule | Local benign flows | Attacks caught (flow-weighted) | Class-balanced detection | Benign FPR | "
          "False alarms per 10k benign |", "|---|---|---|---|---|---|"]

    def row(name, size, d, spread=""):
        return (f"| {name} | {size} | {d['recall']:.3f}{spread} | {d['macro_detection']:.3f} | {d['fpr']:.4f} | "
                f"{d['false_alarms_per_10k']:.0f} |")
    md.append(row("As deployed (no calibration)", "0", res["deployed"]))
    for (size, rule), g in runs.groupby(["size", "rule"], sort=True):
        mean = g[["recall", "macro_detection", "fpr", "false_alarms_per_10k"]].mean().to_dict()
        md.append(row(rule.capitalize(), f"{size:,}", mean, f" ({g['recall'].min():.3f}–{g['recall'].max():.3f})"))
    md.append(row("Ceiling: trained on the target", "all labels", res["ceiling"]))
    best = runs.groupby(["size", "rule"])["macro_detection"].mean().idxmax()
    pick = runs[(runs["size"] == best[0]) & (runs["rule"] == best[1])]
    per = pd.DataFrame(list(pick["per_class"])).mean().sort_values(ascending=False)
    before = pd.Series(res["deployed"]["per_class"])
    md += ["", f"Per-class detection, best rule (**{best[1]}**, {best[0]:,} local flows) vs as deployed:", "",
           "| Class | As deployed | After calibration |", "|---|---|---|"]
    md += [f"| {c} | {before.get(c, float('nan')):.3f} | {v:.3f} |" for c, v in per.items()]
    return md


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--test-cap", type=int, default=50000)
    ap.add_argument("--sizes", default="1000,5000,20000")
    ap.add_argument("--seeds", default="42,1,2")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--results", default="docs/results/local_calibration.md")
    args = ap.parse_args()
    args.sizes = [int(s) for s in args.sizes.split(",")]
    args.seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    data = [load(args.a, args.cap, args.test_cap), load(args.b, args.cap, args.test_cap)]
    feats = [f for f in feature_columns(data[0]["test"]) if f in set(feature_columns(data[1]["test"]))]
    results = [run_direction(data[0], data[1], feats, args), run_direction(data[1], data[0], feats, args)]
    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "target_fpr": args.target_fpr,
           "sizes": args.sizes, "seeds": args.seeds, "data_seed": SEED, "directions": results,
           "minutes": (time.perf_counter() - t0) / 60}
    cmd = (f"python scripts/local_calibration_eval.py {args.a} {args.b} --sizes {','.join(map(str, args.sizes))} "
           f"--seeds {','.join(map(str, args.seeds))} --target-fpr {args.target_fpr}")
    md = ["# Local calibration: adapting to a new network with its own normal traffic", "",
          f"Generated by `{cmd}` on {res['generated']}. Model: {args.model.upper()}. False-alarm budget "
          f"{args.target_fpr:.0%} on a local benign hold-out. Only benign flows from the target's earliest "
          "(training) period are used for calibration; scoring uses its later test period. Ranges in brackets "
          "are min–max over calibration seeds.", ""]
    for r in results:
        md += table(r) + [""]
    md += ["Accuracy is not reported (rule 4). Class-balanced detection averages per-class detection so large DoS "
           "classes cannot dominate.", f"Total run time {res['minutes']:.1f} min."]
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(md) + "\n", encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"results in {out}")


if __name__ == "__main__":
    main()
