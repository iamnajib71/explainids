"""Turn scored flows into alert records (schema: docs/specs/alert_schema.md) and aggregate them."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pandas as pd

from .data import BENIGN
from .threat import context_for, display_name

SEVERITY_RANK = {"Info": 0, "Medium": 1, "High": 2, "Critical": 3}


def build_alerts(flows: pd.DataFrame, predicted, proba, anomaly_scores=None, outliers=None,
                 explanations=None, source_col: str = "Src IP") -> list[dict]:
    alerts = []
    for i, label in enumerate(predicted):
        is_out = bool(outliers[i]) if outliers is not None else False
        if label == BENIGN and not is_out:
            continue
        ctx = context_for(label, is_out)
        alerts.append({
            "alert_id": str(uuid.uuid4()),
            "time": str(flows.iloc[i].get("Timestamp", datetime.now(timezone.utc).isoformat())),
            "source": str(flows.iloc[i].get(source_col, "unknown")),
            "predicted_class": label,
            "confidence": float(max(proba[i])) if proba is not None else None,
            "outlier": is_out,
            "anomaly_score": float(anomaly_scores[i]) if anomaly_scores is not None else None,
            "attack": ctx.to_dict(),
            "severity": ctx.severity,
            "summary": plain_summary(label, ctx, is_out),
            "explanation": explanations[i] if explanations else [],
            "status": "open",
        })
    return alerts


def plain_summary(label: str, ctx, is_outlier: bool) -> str:
    """At most ~30 words for non-specialist owners (US1)."""
    if label == BENIGN and is_outlier:
        return "Unusual network traffic that matches no known attack. Ask your IT support to review it."
    tech = f" ({ctx.technique_id})" if ctx.technique_id else ""
    return f"Possible {display_name(label)}{tech}, {ctx.severity.lower()} severity. {ctx.guidance.split(';')[0]}."


def aggregate(alerts: list[dict], window_minutes: int = 10) -> list[dict]:
    """Group alerts by source host, candidate technique and time window (FR6)."""
    if not alerts:
        return []
    df = pd.DataFrame(alerts)
    t = pd.to_datetime(df["time"], errors="coerce", utc=True, format="mixed")
    df["window"] = t.dt.floor(f"{window_minutes}min").astype(str)
    df["technique"] = df["attack"].map(lambda a: a.get("technique_id") or a.get("technique"))
    groups = []
    for (src, tech, win), g in df.groupby(["source", "technique", "window"], dropna=False):
        groups.append({"source": src, "technique": tech, "window": win, "count": int(len(g)),
                       "classes": sorted(g["predicted_class"].unique().tolist()),
                       "max_severity": max(g["severity"], key=lambda s: SEVERITY_RANK.get(s, 0)),
                       "alert_ids": g["alert_id"].tolist()})
    return sorted(groups, key=lambda x: (-SEVERITY_RANK.get(x["max_severity"], 0), -x["count"]))
