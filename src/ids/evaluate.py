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
