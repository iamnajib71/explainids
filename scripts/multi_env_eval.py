"""Multi-environment evaluation with optional matched target-only controls.

Small-label samples are oracle class-balanced draws from earlier per-class training
partitions, not first incidents. Training caps never cap test sets. --target-only
shares target fitting/calibration budgets; --benign-eval adds regression captures.
See docs/specs/service_regression.md. Use a new results path for matched runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ids import SEED
from ids.data import BENIGN, LABEL_COL, canonical_label, dedup_global, feature_columns, temporal_split
from ids.evaluate import binary_report, report
from ids.models import Detector
from ids.scoring import align_columns

SHORT = {"cicids2017": "2017", "csecicids2018": "2018"}


def short(name: str) -> str:
    return SHORT.get(name, name)


def load(path: str, cap: int) -> dict:
    df = dedup_global(pd.read_parquet(path))
    train, val, test = temporal_split(df)
    # Keep original identities for overlap audits; the historical cap reset them.
    parts = [g.sample(min(len(g), cap), random_state=SEED) for _, g in train.groupby(LABEL_COL)]
    train = pd.concat(parts).sample(frac=1, random_state=SEED)
    return {"name": Path(path).stem, "train": train, "val": val, "test": test}


def few_shot(data: dict, k: int, benign: int, seed: int) -> pd.DataFrame:
    """Oracle-balanced draw from earlier per-class training partitions."""
    if k < 1 or benign < 1:
        raise ValueError("attack and benign sample budgets must be positive")
    tr = data["train"]
    parts = [g.sample(min(k, len(g)), random_state=seed)
             for label, g in tr.groupby(LABEL_COL) if label != BENIGN]
    normal = tr[tr[LABEL_COL] == BENIGN]
    parts.append(normal.sample(min(benign, len(normal)), random_state=seed))
    return pd.concat(parts)


def identity_hash(frame: pd.DataFrame, dataset: str) -> str:
    payload = json.dumps([dataset, sorted(map(str, frame.index))], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def matched_pair(source: dict, target: dict, k: int, benign: int, seed: int,
                 calibration_fraction: float = 0.2) -> list[dict]:
    """Same target annotations; disjoint benign calibration counted inside budget."""
    if not 0 < calibration_fraction < 1:
        raise ValueError("calibration fraction must be between zero and one")
    for data in (source, target):
        indexes = [set(data[key].index) for key in ("train", "val", "test")]
        if any(not data[key].index.is_unique for key in ("train", "val", "test")):
            raise ValueError("processed-row identities must be unique within partitions")
        if indexes[0] & indexes[1] or indexes[0] & indexes[2] or indexes[1] & indexes[2]:
            raise ValueError("training, validation and test row identities must be disjoint")
    local = few_shot(target, k, benign, seed)
    normal = local[local[LABEL_COL] == BENIGN].copy()
    if len(normal) < 2:
        raise ValueError("matched control needs at least two sampled benign rows")
    normal["_order"] = pd.to_datetime(normal["Timestamp"], format="mixed", errors="raise")
    normal = normal.sort_values("_order", kind="stable").drop(columns="_order")
    count = min(len(normal) - 1, math.ceil(len(normal) * calibration_fraction))
    calibration = normal.tail(count).copy()
    target_fit = local.drop(index=calibration.index).copy()
    accounting = {
        "policy": "oracle-balanced earlier target partitions; reserved target benign calibration within budget",
        "requested_attack_rows_per_class": k, "requested_total_target_benign_rows": benign,
        "sampled_target_class_counts": {str(c): int(n) for c, n in local[LABEL_COL].value_counts().items()},
        "target_annotation_rows": len(local), "target_fitting_rows": len(target_fit),
        "target_calibration_benign_rows": len(calibration),
        "source_validation_rows_inspected": 0, "extra_target_validation_rows_inspected": 0,
        "target_sample_identity_sha256": identity_hash(local, target["name"]),
        "target_fit_identity_sha256": identity_hash(target_fit, target["name"]),
        "target_calibration_identity_sha256": identity_hash(calibration, target["name"]),
        "calibration_policy": "identical disjoint target-benign rows; no source validation",
        "identity_namespace": target["name"],
    }
    return [
        {"config": f"few-shot matched: {short(source['name'])} + {short(target['name'])} labels",
         "train": pd.concat([source["train"], target_fit]), "calibration": calibration,
         "label_accounting": {**accounting, "source_training_rows": len(source["train"])}},
        {"config": f"target-only matched: {short(target['name'])} labels (source {short(source['name'])} control)",
         "train": target_fit.copy(), "calibration": calibration.copy(),
         "label_accounting": {**accounting, "source_training_rows": 0}},
    ]


def fit(train: pd.DataFrame, val: pd.DataFrame, feats: list[str], model: str) -> Detector:
    det = Detector(model).fit(train[feats], train[LABEL_COL])
    det.fit_anomaly(train[train[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(val[val[LABEL_COL] == BENIGN][feats])
    return det


def binary_metrics(y: pd.Series, flagged: np.ndarray) -> dict:
    result = binary_report(y, flagged)
    if result["tp"] + result["fn"] == 0:
        result["recall"] = result["f1"] = float("nan")
    if result["tp"] + result["fp"] == 0:
        result["precision"] = float("nan")
    return result


def score(det: Detector, test: pd.DataFrame, feats: list[str], common: list[str]) -> dict:
    aligned, missing = align_columns(test, feats)
    if missing:
        raise ValueError(f"missing model features: {missing}")
    X = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(X.to_numpy(dtype=float)).all(axis=1)
    X, y = X.loc[valid], aligned.loc[valid, LABEL_COL].map(canonical_label)
    if X.empty:
        raise ValueError("evaluation has no valid numeric observations")
    pred = det.predict(X)
    outlier = det.anomaly(X)[1] if det.iforest is not None else np.zeros(len(X), dtype=bool)
    classifier = pred != BENIGN
    flagged = classifier | outlier
    rep = binary_metrics(y, flagged)
    detection = pd.Series(flagged, index=y.index).groupby(y).mean().drop(BENIGN, errors="ignore")
    labels = sorted(set(det.classes) | set(y) | set(common))
    attribution = report(y, pred, labels)
    table = attribution["per_class"].copy()
    table["seen_in_training"] = table.index.isin(det.classes)
    macro_common = table.loc[common, ["precision", "recall", "f1"]].mean().to_dict() if common else {}
    return {
        "flows": len(y), "dropped_invalid": int((~valid).sum()),
        "precision": rep["precision"], "recall": rep["recall"], "f1": rep["f1"],
        "recall_ci": rep["recall_ci"], "fpr": rep["fpr"], "fpr_ci": rep["fpr_ci"],
        "false_alarms_per_10k": 1e4 * rep["fpr"], "macro_detection": float(detection.mean()),
        "macro_f1_common": macro_common.get("f1", float("nan")), "per_class": detection.to_dict(),
        "classifier": binary_metrics(y, classifier), "anomaly": binary_metrics(y, outlier), "with_anomaly": rep,
        "attribution": {"macro_observed": attribution["macro"], "macro_common": macro_common,
                        "per_class": table.reset_index(names="class").to_dict("records"),
                        "labels": labels, "confusion": attribution["confusion"].values.tolist()},
    }


def score_lab(det: Detector, lab: pd.DataFrame) -> dict:
    return score(det, lab, det.features, [])


def json_safe(value):
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, (float, np.floating)):
        return float(value) if np.isfinite(value) else None
    if isinstance(value, np.integer):
        return int(value)
    return value


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--lab", default=None, help="labelled scenario flows, never fitted")
    ap.add_argument("--benign-eval", nargs="+", default=[], metavar="CSV", help="separate labelled all-benign captures")
    ap.add_argument("--target-only", action="store_true", help="paired fitting/calibration label-budget controls")
    ap.add_argument("--calibration-fraction", type=float, default=0.2)
    ap.add_argument("--model", choices=["lgbm", "rf", "xgb"], default="lgbm")
    ap.add_argument("--cap", type=positive, default=60000)
    ap.add_argument("--shots", default="10,50,200")
    ap.add_argument("--seeds", default="42,1")
    ap.add_argument("--local-benign", type=positive, default=1000)
    ap.add_argument("--results", default="docs/results/multi_env.md")
    args = ap.parse_args()
    if args.target_only and args.results == "docs/results/multi_env.md":
        ap.error("matched controls change the calibration protocol; provide a new --results path")
    if args.target_only and args.local_benign < 2:
        ap.error("matched controls need at least two benign labels for disjoint fitting/calibration")
    try:
        shots = [positive(s) for s in args.shots.split(",")]
        seeds = [int(s) for s in args.seeds.split(",")]
        if any(s < 0 or s >= 2**32 for s in seeds):
            raise ValueError("seeds must be in [0, 2**32)")
        if not 0 < args.calibration_fraction < 1:
            raise ValueError("calibration fraction must be between zero and one")
    except (ValueError, argparse.ArgumentTypeError) as exc:
        ap.error(str(exc))
    t0 = time.perf_counter()
    A, B = load(args.a, args.cap), load(args.b, args.cap)
    feats = [f for f in feature_columns(A["test"]) if f in set(feature_columns(B["test"]))]
    common = sorted(set(A["test"][LABEL_COL]) & set(B["test"][LABEL_COL]))
    lab = pd.read_csv(args.lab, low_memory=False) if args.lab else None
    benign_frames = {}
    for i, path in enumerate(args.benign_eval):
        frame = pd.read_csv(path, low_memory=False)
        if LABEL_COL not in frame or frame.empty or not frame[LABEL_COL].map(canonical_label).eq(BENIGN).all():
            ap.error(f"benign evaluation requires nonempty all-benign labels: {path}")
        benign_frames[f"benign:{i}:{Path(path).parent.name}"] = frame
    rows = []

    def run(name: str, train: pd.DataFrame, val: pd.DataFrame, **meta) -> None:
        det = fit(train, val, feats, args.model)
        if "label_accounting" not in meta:
            meta["label_accounting"] = {"training_rows": len(train), "validation_rows_inspected": len(val),
                                        "calibration_benign_rows": int(val[LABEL_COL].eq(BENIGN).sum()),
                                        "policy": "legacy baseline; validation access differs from matched conditions"}
        row = {"config": name, **meta,
               "tests": {short(d["name"]): score(det, d["test"], feats, common) for d in (A, B)}}
        if lab is not None:
            row["tests"]["lab"] = score_lab(det, lab)
        row["tests"].update({key: score_lab(det, frame) for key, frame in benign_frames.items()})
        rows.append(row)
        print(name + ": " + " | ".join(f"{key} det {fmt(v['macro_detection'])} FPR {fmt(v['fpr'])}"
                                          for key, v in row["tests"].items()), flush=True)

    run(f"single: {short(A['name'])}", A["train"], A["val"])
    run(f"single: {short(B['name'])}", B["train"], B["val"])
    run("both environments", pd.concat([A["train"], B["train"]]), pd.concat([A["val"], B["val"]]))
    for src, tgt in ((A, B), (B, A)):
        for k in shots:
            for seed in seeds:
                if args.target_only:
                    for condition in matched_pair(src, tgt, k, args.local_benign, seed, args.calibration_fraction):
                        run(condition["config"], condition["train"], condition["calibration"],
                            label_accounting=condition["label_accounting"], k=k, seed=seed, target=short(tgt["name"]))
                else:
                    local = few_shot(tgt, k, args.local_benign, seed)
                    run(f"few-shot: {short(src['name'])} + {short(tgt['name'])} labels",
                        pd.concat([src["train"], local]), src["val"], k=k, seed=seed, target=short(tgt["name"]),
                        label_accounting={"source_training_rows": len(src["train"]), "target_annotation_rows": len(local),
                                          "target_sample_identity_sha256": identity_hash(local, tgt["name"]),
                                          "source_validation_rows_inspected": len(src["val"]),
                                          "calibration_benign_rows": int(src["val"][LABEL_COL].eq(BENIGN).sum()),
                                          "policy": "legacy oracle-balanced target sample; source validation threshold"})
    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "cap": args.cap, "data_seed": SEED,
           "focus": short(B["name"]), "target_only": args.target_only,
           "calibration_fraction": args.calibration_fraction, "sampling_seeds": seeds,
           "common_classes": common, "local_benign": args.local_benign, "lab": args.lab,
           "benign_evaluation_inputs": dict(zip(benign_frames, args.benign_eval)), "runs": rows,
           "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res, args), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(json_safe(res), indent=1, allow_nan=False), encoding="utf-8")
    print(f"results in {out}")


def fmt(value, percent: bool = False) -> str:
    if value is None or not np.isfinite(value):
        return "N/A"
    return f"{value:.2%}" if percent else f"{value:.3f}"


def to_markdown(res: dict, args) -> str:
    tests = list(res["runs"][0]["tests"])
    command = (f"python scripts/multi_env_eval.py {args.a} {args.b} --model {args.model} --cap {args.cap} "
               f"--shots {args.shots} --seeds {args.seeds} --local-benign {args.local_benign} "
               f"--calibration-fraction {args.calibration_fraction} --results {args.results}")
    if args.target_only:
        command += " --target-only"
    if args.lab:
        command += f" --lab {args.lab}"
    if args.benign_eval:
        command += " --benign-eval " + " ".join(args.benign_eval)
    md = ["# Multi-environment and matched-label evaluation", "", f"Generated by `{command}` on {res['generated']}.", "",
          "Training is capped per class; test partitions are full. Target labels are oracle-balanced draws from earlier "
          "per-class partitions, not first incidents. Seeds vary label selection; model seed stays fixed.", "",
          "Matched conditions share exact target rows and reserve benign calibration inside the annotation budget. "
          "They use no source validation or extra target validation. Legacy baselines retain disclosed validation access. "
          "Matched results are not interchangeable with historical source-calibrated few-shot results.", "",
          "## Summary: class-balanced attack detection / benign FPR", "",
          "| Training | " + " | ".join(f"Test on {t}" for t in tests) + " |", "|---|" + "---|" * len(tests)]
    df = pd.DataFrame([{"config": r["config"], "k": r.get("k"), **{t: r["tests"][t] for t in tests}} for r in res["runs"]])
    for (config, k), group in df.groupby(["config", "k"], dropna=False, sort=False):
        cells = [f"{fmt(np.mean([v['macro_detection'] for v in group[t]]))} / "
                 f"{fmt(np.mean([v['fpr'] for v in group[t]]), True)}" for t in tests]
        label = config + (f", k = {int(k)}" if pd.notna(k) else "")
        md.append(f"| {label} | " + " | ".join(cells) + " |")
    md += ["", "N/A means an absent denominator, including attack detection in all-benign captures. "
           "Unknown-class detection as another attack is not correct attribution. Wilson intervals in JSON are nominal "
           "flow-level intervals; clustered captures are not independent networks."]
    for i, run in enumerate(res["runs"]):
        md += ["", f"## Run {i}: {run['config']} (k={run.get('k', 'N/A')}, sample seed={run.get('seed', 'N/A')})", "",
               "Label accounting: `" + json.dumps(run["label_accounting"], sort_keys=True) + "`."]
        for name, result in run["tests"].items():
            attr = result["attribution"]
            md += ["", f"### {name}: {result['flows']:,} scored, {result['dropped_invalid']:,} invalid excluded", "",
                   "| Alert rule | Precision | Recall | F1 | Benign FPR | TP | FP | FN | TN |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for rule in ("classifier", "anomaly", "with_anomaly"):
                binary = result[rule]
                md.append(f"| {rule} | " + " | ".join(fmt(binary[key], key == "fpr") for key in ("precision", "recall", "f1", "fpr"))
                          + " | " + " | ".join(str(binary[key]) for key in ("tp", "fp", "fn", "tn")) + " |")
            md += ["", "Observed-class attribution macro P/R/F1: "
                   + " / ".join(fmt(attr["macro_observed"][key]) for key in ("precision", "recall", "f1")) + ".",
                   "Common-class attribution macro P/R/F1: "
                   + " / ".join(fmt(attr["macro_common"].get(key)) for key in ("precision", "recall", "f1")) + ".", "",
                   "| Class | Precision | Recall | F1 | Support | Seen in training | Any-alert detection |", "|---|---:|---:|---:|---:|---|---:|"]
            for row in attr["per_class"]:
                md.append(f"| {row['class']} | " + " | ".join(fmt(row[key]) for key in ("precision", "recall", "f1"))
                          + f" | {row['support']} | {'yes' if row['seen_in_training'] else 'no'} | {fmt(result['per_class'].get(row['class']))} |")
            labels = attr["labels"]
            md += ["", "Confusion matrix (rows true, columns predicted):", "",
                   "| True / predicted | " + " | ".join(labels) + " |", "|---|" + "---:|" * len(labels)]
            md += [f"| {labels[j]} | " + " | ".join(str(value) for value in row) + " |" for j, row in enumerate(attr["confusion"])]
    md += ["", "Accuracy is not reported. Benign profiles are regression checks, not unseen production networks.",
           f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    main()
