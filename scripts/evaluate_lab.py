"""Score labelled lab flows with the trained detector: the third generalisation test, on our own traffic.

Usage:
  python scripts/evaluate_lab.py lab/flows_labelled.csv --model-dir models --results docs/results/lab_eval.md

Uses the same column alignment and invalid-row policy as the API's CSV upload. Reports alert-level
recall/precision/FPR for the classifier alone and with the Isolation Forest (the deployed alert rule),
per-scenario detection, per-class attribution metrics for all evaluated labels, and the confusion matrix.
Classes the model never saw (e.g. SYN-Flood) count as detected when any alert fires, not as correctly
attributed to that unseen class.

Real-world reading: every rate carries a 95% Wilson interval (small lab samples cannot show "exactly 0%"),
and the alert burden is reported as false alarms per 10,000 benign flows, per hour of capture, and, with
--benign-flows-per-hour, projected to a stated network volume.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ids.data import BENIGN, LABEL_COL, canonical_label
from ids.evaluate import binary_report, report, wilson_interval
from ids.scoring import align_columns


def alert_burden(fp: int, benign: int, hours: float | None, benign_per_hour: float | None) -> dict:
    """False alarms an operator would face, with the 95% interval carried through every projection."""
    lo, hi = wilson_interval(fp, benign)
    out = {"per_10k": 1e4 * fp / benign if benign else float("nan"), "per_10k_ci": (1e4 * lo, 1e4 * hi),
           "per_capture_hour": fp / hours if hours else None}
    if benign_per_hour:
        out.update(benign_flows_per_hour=benign_per_hour, projected_per_hour=benign_per_hour * fp / benign,
                   projected_per_hour_ci=(benign_per_hour * lo, benign_per_hour * hi))
    return out


def capture_hours(df: pd.DataFrame) -> float | None:
    col = next((c for c in df.columns if c.strip().lower() == "timestamp"), None)
    if col is None:
        return None
    ts = pd.to_datetime(df[col], format="mixed", errors="coerce").dropna()
    span = (ts.max() - ts.min()).total_seconds() / 3600 if len(ts) > 1 else 0
    return span or None


def evaluate(det, df: pd.DataFrame, benign_per_hour: float | None = None) -> dict:
    df, missing = align_columns(df, det.features)
    if missing:
        raise ValueError(f"{len(missing)} model features missing, e.g. {missing[:6]}")
    X = df[det.features].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(X.to_numpy(dtype=float)).all(axis=1)
    X, y = X[valid], df.loc[valid, LABEL_COL].map(canonical_label)
    pred = det.predict(X)
    outlier = det.anomaly(X)[1] if det.iforest is not None else np.zeros(len(X), dtype=bool)
    flagged = (pred != BENIGN) | outlier
    known = sorted(set(det.classes) & set(y))
    rep = report(y, pred, sorted(set(det.classes) | set(y)))
    per_class = rep["per_class"].copy()
    per_class["seen_in_training"] = per_class.index.isin(det.classes)
    per = pd.DataFrame({"truth": y.to_numpy(), "clf": pred != BENIGN, "any": flagged})
    scen = per.groupby("truth").agg(flows=("clf", "size"), classifier=("clf", "mean"), with_anomaly=("any", "mean"))
    scen["seen_in_training"] = [c in det.classes for c in scen.index]
    flagged_n = per.groupby("truth")["any"].sum()
    scen["with_anomaly_ci"] = [wilson_interval(int(flagged_n[c]), int(scen.loc[c, "flows"])) for c in scen.index]
    any_rep = binary_report(y, flagged)
    benign_n = int((y == BENIGN).sum())
    return {"flows": int(len(y)), "dropped_invalid": int((~valid).sum()),
            "classifier": binary_report(y, pred != BENIGN), "with_anomaly": any_rep,
            "capture_hours": capture_hours(df[valid]),
            "alert_burden": alert_burden(any_rep["fp"], benign_n, capture_hours(df[valid]), benign_per_hour),
            "macro_known": rep["per_class"].loc[known, ["precision", "recall", "f1"]].mean().to_dict(),
            "macro_observed": rep["per_class"].loc[sorted(set(y)), ["precision", "recall", "f1"]].mean().to_dict(),
            "per_class": per_class.reset_index(names="class").to_dict("records"),
            "per_scenario": scen.reset_index(names="class").to_dict("records"),
            "labels": list(rep["confusion"].index), "confusion": rep["confusion"].values.tolist()}


def ci(bounds, d: int = 3) -> str:
    lo, hi = bounds
    return f"{lo:.{d}f}–{hi:.{d}f}"


def burden_lines(res: dict) -> list[str]:
    b = res["alert_burden"]
    lines = [f"- False alarms per 10,000 benign flows: **{b['per_10k']:.1f}** (95% interval {b['per_10k_ci'][0]:.1f}–"
             f"{b['per_10k_ci'][1]:.1f})."]
    if b.get("per_capture_hour") is not None:
        lines.append(f"- Over this capture ({res['capture_hours'] * 60:.1f} min): {b['per_capture_hour']:.1f} false alarms per hour "
                     "at the lab's own traffic rate.")
    if b.get("projected_per_hour") is not None:
        lo, hi = b["projected_per_hour_ci"]
        lines.append(f"- Projected at {b['benign_flows_per_hour']:,.0f} benign flows per hour: **{b['projected_per_hour']:.1f}** "
                     f"false alarms per hour (95% interval {lo:.1f}–{hi:.1f}).")
    if res["flows"] < 10_000:
        lines.append(f"- Only {res['flows']:,} flows: these figures validate the pipeline; they are not evidence of "
                     "real-world alert burden.")
    return lines


def to_markdown(res: dict, cmd: str) -> str:
    c, a = res["classifier"], res["with_anomaly"]
    md = ["# Lab traffic evaluation", "", f"Generated by `{cmd}` on {res['generated']}. Model: {res['model']}.",
          f"{res['flows']:,} flows scored ({res['dropped_invalid']:,} with invalid values skipped).", "",
          "| Alert rule | Attacks caught (recall) | Alert precision | Benign FPR |", "|---|---|---|---|",
          f"| Classifier | {c['recall']:.3f} | {c['precision']:.3f} | {c['fpr']:.4f} |",
          f"| Classifier or anomaly (deployed) | {a['recall']:.3f} | {a['precision']:.3f} | {a['fpr']:.4f} |", "",
          f"95% intervals (deployed rule): recall {ci(a['recall_ci'])}; benign FPR {ci(a['fpr_ci'], 4)}.", "",
          "## Alert burden (deployed rule)", ""] + burden_lines(res) + ["",
          f"Macro precision / recall / F1 over classes the model knows: {res['macro_known']['precision']:.3f} / "
          f"{res['macro_known']['recall']:.3f} / {res['macro_known']['f1']:.3f}.", "",
          "Macro precision / recall / F1 over all observed truth classes (including unseen): "
          f"{res['macro_observed']['precision']:.3f} / {res['macro_observed']['recall']:.3f} / "
          f"{res['macro_observed']['f1']:.3f}.", "",
          "| Class | Flows | Seen in training | Flagged by classifier | Flagged incl. anomaly | 95% interval |",
          "|---|---|---|---|---|---|"]
    md += [f"| {s['class']} | {s['flows']:,} | {'yes' if s['seen_in_training'] else 'no'} | {s['classifier']:.3f} | "
           f"{s['with_anomaly']:.3f} | {ci(s['with_anomaly_ci'])} |" for s in res["per_scenario"]]
    md += ["", "For BENIGN, the flagged columns are false-positive rates. Accuracy is not reported (rule 4).", "",
           "## Per-class attribution (classifier only)", "",
           "| Class | Precision | Recall | F1 | Support | Seen in training |", "|---|---:|---:|---:|---:|---|"]
    md += [f"| {s['class']} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | "
           f"{s['support']:,} | {'yes' if s['seen_in_training'] else 'no'} |" for s in res["per_class"]]
    md += ["", "Unseen scenarios can be detected by any attack or anomaly alert without being correctly attributed. "
           "Their detection rates are in the scenario table; the attribution metrics and confusion matrix "
           "use the classifier's predicted class only. Undefined per-class metrics are shown as zero."]
    labels = res["labels"]
    md += ["", "## Confusion matrix (rows = true, columns = predicted)", "",
           "| | " + " | ".join(labels) + " |", "|---|" + "---:|" * len(labels)]
    md += [f"| {labels[i]} | " + " | ".join(f"{v:,}" for v in row) + " |" for i, row in enumerate(res["confusion"])]
    return "\n".join(md) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flows")
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--results", default="docs/results/lab_eval.md")
    ap.add_argument("--benign-flows-per-hour", type=float, default=None,
                    help="project false alarms to this benign volume (state where the figure comes from)")
    args = ap.parse_args()
    det = joblib.load(Path(args.model_dir) / "detector.joblib")
    card_path = Path(args.model_dir) / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
    df = pd.read_csv(args.flows, low_memory=False)
    res = {**evaluate(det, df, args.benign_flows_per_hour), "generated": time.strftime("%Y-%m-%d"),
           "model": f"{det.name.upper()} trained on {card.get('dataset', 'unknown')}"}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res, f"python scripts/evaluate_lab.py {args.flows} --model-dir {args.model_dir}"), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"recall {res['with_anomaly']['recall']:.3f} | FPR {res['with_anomaly']['fpr']:.4f} | results in {out}")


if __name__ == "__main__":
    main()
