"""Multi-environment training and few-shot local labels: do they recover what transfer loses?

Usage:
  python scripts/multi_env_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab data/lab/run_20261025T051149Z/flows_labelled.csv --shots 10,50,200 --seeds 42,1 \
      --results docs/results/multi_env.md

Every model is scored on the held-out later test period of BOTH datasets and, with --lab, on our own
lab traffic (a third environment no model trains on).

Training configurations:
  single environment   trained on one dataset's training period (the deployed situation)
  both environments    trained on both datasets' training periods together
  few-shot local       one dataset + a site's first labelled incidents: k flows of every attack class from the
                       other dataset's EARLIEST period (its training split) plus 1,000 of its benign flows.
                       This is what an analyst confirming a handful of alerts would produce.
The few-shot flows come only from the target's training period, so the target's test period stays unseen.
Recall is reported flow-weighted and class-balanced (each attack class counts once), with 95% Wilson
intervals; false alarms per 10,000 benign flows show the alert burden.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as a script or import from tests

from ids import SEED
from ids.data import BENIGN, LABEL_COL, dedup_global, feature_columns, stratified_sample, temporal_split
from ids.evaluate import binary_report, report
from ids.models import Detector
from scripts.evaluate_lab import evaluate as evaluate_lab

SHORT = {"cicids2017": "2017", "csecicids2018": "2018"}


def short(name: str) -> str:
    return SHORT.get(name, name)


def load(path: str, cap: int) -> dict:
    df = dedup_global(pd.read_parquet(path))
    train, val, test = temporal_split(df)
    return {"name": Path(path).stem, "train": stratified_sample(train, cap), "val": val, "test": test}


def few_shot(data: dict, k: int, benign: int, seed: int) -> pd.DataFrame:
    """A site's first labelled incidents: k flows per attack class plus some normal traffic, earliest period only."""
    tr = data["train"]
    parts = [g.sample(min(k, len(g)), random_state=seed) for label, g in tr.groupby(LABEL_COL) if label != BENIGN]
    parts.append(tr[tr[LABEL_COL] == BENIGN].sample(min(benign, (tr[LABEL_COL] == BENIGN).sum()), random_state=seed))
    return pd.concat(parts)


def fit(train: pd.DataFrame, val: pd.DataFrame, feats: list[str], model: str) -> Detector:
    det = Detector(model).fit(train[feats], train[LABEL_COL])
    det.fit_anomaly(train[train[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(val[val[LABEL_COL] == BENIGN][feats])
    return det


def score(det: Detector, test: pd.DataFrame, feats: list[str], common: list[str]) -> dict:
    X, y = test[feats], test[LABEL_COL]
    pred = det.predict(X)
    flagged = (pred != BENIGN) | det.anomaly(X)[1]
    rep = binary_report(y, flagged)
    per_class = pd.Series(flagged, index=y.index).groupby(y).mean().drop(BENIGN, errors="ignore")
    attribution = report(y, pred, sorted(set(det.classes) | set(y)))["per_class"]
    return {"recall": rep["recall"], "recall_ci": rep["recall_ci"], "fpr": rep["fpr"], "fpr_ci": rep["fpr_ci"],
            "false_alarms_per_10k": 1e4 * rep["fpr"], "macro_detection": float(per_class.mean()),
            "macro_f1_common": float(attribution.loc[common, "f1"].mean()), "per_class": per_class.round(4).to_dict()}


def score_lab(det: Detector, lab: pd.DataFrame) -> dict:
    r = evaluate_lab(det, lab)
    scen = {s["class"]: s for s in r["per_scenario"]}
    attacks = [s for c, s in scen.items() if c != BENIGN]
    return {"flows": r["flows"], "recall": r["with_anomaly"]["recall"], "recall_ci": r["with_anomaly"]["recall_ci"],
            "fpr": r["with_anomaly"]["fpr"], "fpr_ci": r["with_anomaly"]["fpr_ci"],
            "macro_detection": float(np.mean([s["with_anomaly"] for s in attacks])),
            "per_class": {c: s["with_anomaly"] for c, s in scen.items() if c != BENIGN}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--lab", default=None, help="labelled lab flows (CSV) used as a third, unseen environment")
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--shots", default="10,50,200")
    ap.add_argument("--seeds", default="42,1")
    ap.add_argument("--local-benign", type=int, default=1000)
    ap.add_argument("--results", default="docs/results/multi_env.md")
    args = ap.parse_args()
    shots = [int(s) for s in args.shots.split(",")]
    seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    A, B = load(args.a, args.cap), load(args.b, args.cap)
    feats = [f for f in feature_columns(A["test"]) if f in set(feature_columns(B["test"]))]
    common = sorted(set(A["test"][LABEL_COL]) & set(B["test"][LABEL_COL]))
    lab = pd.read_csv(args.lab, low_memory=False) if args.lab else None
    rows = []

    def run(name: str, train: pd.DataFrame, val: pd.DataFrame, **meta):
        det = fit(train, val, feats, args.model)
        row = {"config": name, **meta,
               "tests": {short(d["name"]): score(det, d["test"], feats, common) for d in (A, B)}}
        if lab is not None:
            row["tests"]["lab"] = score_lab(det, lab)
        rows.append(row)
        print(f"{name} {meta}: " + " | ".join(f"{k} det {v['macro_detection']:.3f} FPR {v['fpr']:.4f}"
                                             for k, v in row["tests"].items()), flush=True)

    run(f"single: {short(A['name'])}", A["train"], A["val"])
    run(f"single: {short(B['name'])}", B["train"], B["val"])
    run("both environments", pd.concat([A["train"], B["train"]]), pd.concat([A["val"], B["val"]]))
    for src, tgt in ((A, B), (B, A)):
        for k in shots:
            for seed in seeds:
                local = few_shot(tgt, k, args.local_benign, seed)
                run(f"few-shot: {short(src['name'])} + {short(tgt['name'])} labels", pd.concat([src["train"], local]),
                    src["val"], k=k, seed=seed, target=short(tgt["name"]))

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "cap": args.cap, "data_seed": SEED,
           "focus": short(B["name"]),
           "common_classes": common, "local_benign": args.local_benign, "lab": args.lab, "runs": rows,
           "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res, args), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"results in {out}")


def to_markdown(res: dict, args) -> str:
    tests = list(res["runs"][0]["tests"])
    md = ["# Multi-environment training and few-shot local labels", "",
          f"Generated by `python scripts/multi_env_eval.py {args.a} {args.b}"
          f"{' --lab ' + args.lab if args.lab else ''} --shots {args.shots} --seeds {args.seeds}` on {res['generated']}. "
          f"Model: {res['model'].upper()}; training capped at {res['cap']:,} flows per class per dataset. Each cell: "
          "class-balanced detection (each attack class counts once) / benign false-positive rate. Few-shot rows are the "
          f"mean over seeds of k labelled flows per attack class plus {res['local_benign']:,} benign flows from the target's "
          "earliest period.", "",
          "| Training | " + " | ".join(f"Test on {t}" for t in tests) + " |", "|---|" + "---|" * len(tests)]
    df = pd.DataFrame([{"config": r["config"], "k": r.get("k"), **{t: r["tests"][t] for t in tests}} for r in res["runs"]])
    for (config, k), g in df.groupby(["config", "k"], dropna=False, sort=False):
        cells = []
        for t in tests:
            det = np.mean([v["macro_detection"] for v in g[t]])
            fpr = np.mean([v["fpr"] for v in g[t]])
            cells.append(f"{det:.3f} / {fpr:.2%}")
        label = config + (f", k = {int(k)}" if pd.notna(k) else "")
        md.append(f"| {label} | " + " | ".join(cells) + " |")
    md += ["", f"## Per-class detection on {res['focus']} test (the classes single-environment transfer missed)", "",
           "| Training | DoS-Hulk | DDoS-HTTP | DoS-GoldenEye | DDoS-UDP | Infiltration |", "|---|---|---|---|---|---|"]
    for (config, k), g in df.groupby(["config", "k"], dropna=False, sort=False):
        per = pd.DataFrame([v["per_class"] for v in g[res["focus"]]]).mean()
        label = config + (f", k = {int(k)}" if pd.notna(k) else "")
        md.append(f"| {label} | " + " | ".join(f"{per.get(c, float('nan')):.3f}" for c in
                                               ["DoS-Hulk", "DDoS-HTTP", "DoS-GoldenEye", "DDoS-UDP", "Infiltration"]) + " |")
    if "lab" in tests:
        md += ["", "Lab traffic is a small deterministic emulation (see `data/lab`); its rates carry wide intervals and "
               "check transfer of the pipeline, not real-world performance."]
    md += ["", "Accuracy is not reported (rule 4).", f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    main()
