"""Metrics required by the project rules: per-class and macro P/R/F1, confusion matrix,
benign false-positive rate, PR-AUC and latency. Accuracy is never reported on its own."""
from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support

from .data import BENIGN


def benign_fpr(y_true, y_pred) -> float:
    """Share of truly benign flows that were flagged as any attack: FP / (FP + TN)."""
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    benign = y_true == BENIGN
    return float((y_pred[benign] != BENIGN).mean()) if benign.any() else float("nan")


def report(y_true, y_pred, labels: list[str] | None = None) -> dict:
    labels = labels or sorted(set(y_true) | set(y_pred))
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    per_class = pd.DataFrame({"precision": p, "recall": r, "f1": f, "support": s}, index=labels)
    present = per_class["support"] > 0
    return {
        "per_class": per_class,
        "macro": per_class.loc[present, ["precision", "recall", "f1"]].mean().to_dict(),
        "benign_fpr": benign_fpr(y_true, y_pred),
        "confusion": pd.DataFrame(confusion_matrix(y_true, y_pred, labels=labels), index=labels, columns=labels),
    }


def binary_pr_auc(y_true, attack_score) -> float:
    """PR-AUC for attack vs benign, given a per-flow attack score (e.g. 1 - P(benign))."""
    return float(average_precision_score(np.asarray(y_true) != BENIGN, attack_score))


def latency_ms_per_flow(predict, X, repeats: int = 3) -> float:
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        predict(X)
        best = min(best, (time.perf_counter() - t0) / max(len(X), 1))
    return best * 1000


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n. Honest at the extremes: 0/40 is not 'exactly 0%'."""
    if n == 0:
        return float("nan"), float("nan")
    p, z2 = k / n, z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = z * np.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def binary_report(y_true, flagged) -> dict:
    """Attack-vs-benign alert quality for a boolean `flagged` mask (any attack class counts as a hit)."""
    attack, flagged = np.asarray(y_true) != BENIGN, np.asarray(flagged, dtype=bool)
    tp, fp = int((attack & flagged).sum()), int((~attack & flagged).sum())
    fn, tn = int((attack & ~flagged).sum()), int((~attack & ~flagged).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else float("nan"), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall_ci": wilson_interval(tp, tp + fn), "fpr_ci": wilson_interval(fp, fp + tn)}
