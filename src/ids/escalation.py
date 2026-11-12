"""Repetition escalation: demoted anomaly alerts return to the queue when one service receives many in a minute.

A flow is *demoted* when the benchmark anomaly layer flags it, the classifier calls it benign and the site's
exemplar envelope vetoes it. One such flow resembles the site's normal traffic; many to the same destination and
port within a short window do not. The threshold is learned from the site's own earlier traffic, with no labels:
more repetition than the site has ever shown (docs/PREREGISTRATION_ESCALATION.md).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

WINDOW_SECONDS = 60.0
FLOOR = 3


def repeat_counts(t: np.ndarray, key: np.ndarray, demoted: np.ndarray, window: float = WINDOW_SECONDS) -> np.ndarray:
    """For each demoted flow, the number of demoted flows with the same key that started within the `window`
    seconds ending at its start (itself included). Zero for flows that are not demoted."""
    out = np.zeros(len(t), dtype=int)
    idx = np.flatnonzero(demoted)
    if not len(idx):
        return out
    frame = pd.DataFrame({"i": idx, "t": np.asarray(t, dtype=float)[idx], "k": np.asarray(key)[idx]})
    for _, g in frame.sort_values("t", kind="stable").groupby("k", sort=False):
        ts = g["t"].to_numpy()
        first = np.searchsorted(ts, ts - window, side="left")   # earliest flow still inside the window
        last = np.searchsorted(ts, ts, side="right")            # flows that share the start time count too
        out[g["i"].to_numpy()] = last - first
    return out


def threshold_from(counts: np.ndarray, floor: int = FLOOR) -> int:
    """N = 1 + the largest repetition the site's own earlier traffic showed, never below the floor."""
    return max(floor, 1 + int(np.max(counts, initial=0)))


def escalated(t: np.ndarray, key: np.ndarray, demoted: np.ndarray, n: int, window: float = WINDOW_SECONDS) -> np.ndarray:
    """Demoted flows returned to the alert queue under the repetition rule."""
    return np.asarray(demoted, dtype=bool) & (repeat_counts(t, key, demoted, window) >= n)
