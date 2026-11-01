"""Choosing the local benign flows that repair a detector after it moves to a new network."""
from __future__ import annotations

import numpy as np
import pandas as pd

from ids.data import BENIGN


def service_key(df: pd.DataFrame) -> pd.Series:
    """Group flows by destination port so a sample covers every service, not just the common one."""
    port = next((c for c in df.columns if c.strip().lower() in {"dst port", "destination port"}), None)
    return df[port].astype(int).astype(str) if port else pd.Series("all", index=df.index)



def local_sample(pool: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """Exactly n local flows spread across services: one per destination port in turn, busiest first.

    Real traffic has many one-off ports, so proportional stratification would either overshoot n or
    miss services; a round-robin draw keeps the budget fixed and the sample diverse.
    """
    rng = np.random.default_rng(seed)
    groups = {port: list(rng.permutation(np.asarray(idx)))
              for port, idx in pool.groupby(service_key(pool)).groups.items()}
    order = sorted(groups, key=lambda p: (-len(groups[p]), p))
    picked: list = []
    while len(picked) < min(n, len(pool)):
        for port in order:
            if groups[port] and len(picked) < n:
                picked.append(groups[port].pop())
    return pool.loc[picked]


def triage_sample(det, pool: pd.DataFrame, feats: list[str], n: int, seed: int) -> tuple[pd.DataFrame, int]:
    """The repair set an analyst produces by triage: the model's own alerts on earlier local traffic,
    confirmed benign, spread across services; topped up with ordinary local flows if there are fewer
    than n alerts. Returns the sample and how many of its flows were alerts."""
    X = pool[feats]
    flagged = np.asarray((det.predict(X) != BENIGN) | det.anomaly(X)[1])
    alerted = local_sample(pool.loc[flagged], n, seed) if flagged.any() else pool.iloc[:0]
    rest = pool.drop(index=alerted.index)
    top_up = local_sample(rest, n - len(alerted), seed) if len(alerted) < n else rest.iloc[:0]
    return pd.concat([alerted, top_up]), int(len(alerted))


def uncertainty_sample(det, pool: pd.DataFrame, feats: list[str], n: int) -> pd.DataFrame:
    """The n local flows the classifier is least sure about (lowest top-class probability).

    The usual active-learning choice, and the comparison arm for triage: it asks the analyst about the
    flows nearest a decision boundary rather than about the flows that actually raised alerts.
    """
    confidence = det.predict_proba(pool[feats]).max(axis=1)
    order = np.argsort(confidence, kind="stable")[: min(n, len(pool))]
    return pool.iloc[order]
