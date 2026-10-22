"""Score a frame of flows end to end: classify, flag outliers, explain alerts, attach ATT&CK context.

Shared by the API's /predict, the real-traffic replay and CSV uploads so all three behave the same.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .alerts import build_alerts
from .data import BENIGN, LABEL_COL, canonical_label
from .explain import Explainer


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower().replace("packets", "packet"))


def align_columns(df: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, list[str]]:
    """Map loosely named CICFlowMeter columns (spacing, case, plural forms) onto the model's names.

    Returns the renamed frame and the features that are still missing.
    """
    df = df.rename(columns=lambda c: str(c).strip())
    lookup = {_norm(f): f for f in features}
    renames = {c: lookup[_norm(c)] for c in df.columns if c not in features and _norm(c) in lookup}
    df = df.rename(columns=renames)
    return df, [f for f in features if f not in df]


def score_frame(det, explainer: Explainer, df: pd.DataFrame, k: int = 5) -> tuple[pd.DataFrame, list[dict]]:
    """Return per-flow results and alert records (with SHAP explanations) for `df`."""
    X = df[det.features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)
    pred = det.predict(X)
    proba = det.predict_proba(X)
    scores, outliers = det.anomaly(X) if det.iforest is not None else (None, None)
    flagged = [i for i, p in enumerate(pred) if p != BENIGN or (outliers is not None and outliers[i])]
    explanations: list[list[dict]] = [[] for _ in range(len(df))]
    if flagged:
        top = explainer.top_features(X.iloc[flagged], [pred[i] for i in flagged], k=k)
        for i, e in zip(flagged, top):
            explanations[i] = e
    alerts = build_alerts(df.reset_index(drop=True), pred, proba, scores, outliers, explanations)
    flows = pd.DataFrame({"predicted": pred, "confidence": proba.max(axis=1),
                          "outlier": outliers if outliers is not None else False})
    if LABEL_COL in df:
        truth = df[LABEL_COL].map(canonical_label).to_numpy()
        flows["truth"] = truth
        for a, i in zip(alerts, flagged):
            a["truth"] = truth[i]
            a["verdict"] = verdict(truth[i], pred[i])
    return flows, alerts


def interleave_background(df: pd.DataFrame) -> pd.DataFrame:
    """Order a replay as attack episodes (in capture order) over a steady benign background.

    Held-out benign flows come from later in the capture week than held-out attack bursts, so a
    plain time sort would play all attacks first. Spreading benign flows evenly across the stream
    keeps every flow (and its real timestamp and label) while giving a realistic mix.
    """
    benign = df[df[LABEL_COL] == BENIGN].sort_values("Timestamp")
    attacks = df[df[LABEL_COL] != BENIGN].sort_values("Timestamp")
    pos = np.concatenate([np.linspace(0, 1, len(benign), endpoint=False),
                          np.linspace(0, 1, len(attacks), endpoint=False) + 0.5 / max(len(attacks), 1)])
    return pd.concat([benign, attacks]).iloc[np.argsort(pos, kind="stable")].reset_index(drop=True)


def verdict(truth: str, predicted: str) -> str:
    """How an alert compares with the dataset label (only available for labelled data)."""
    if truth == BENIGN:
        return "false positive"
    return "correct" if truth == predicted else "attack, other class"
