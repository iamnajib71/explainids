"""Two-envelope anomaly rule: unusual for the benchmark's normal *and* for the site's normal."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ids import SEED


class TwoEnvelope:
    """A flow is anomalous only if it is unusual for the benchmark's normal *and* for this site's normal.

    The benchmark-trained anomaly detector flags whatever falls outside the benign envelope it was fitted
    on; on a modern network that includes ordinary bulk transfers larger than anything in the benchmark.
    A second isolation forest, fitted on the site's own earlier traffic (70%) with its threshold set on
    the rest (30%) at the same 1% budget, vetoes those. No labels are used.
    """

    def __init__(self, det, local: pd.DataFrame, budget: float = 0.01, seed: int = SEED):
        self.det, self.features = det, det.features
        order = np.random.default_rng(seed).permutation(len(local))
        cut = int(len(local) * 0.7)
        fit, cal = local.iloc[order[:cut]], local.iloc[order[cut:]]
        self.local = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(det._anomaly_input(fit))
        self.local_threshold = float(np.quantile(self.local.score_samples(det._anomaly_input(cal)), budget))

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.det.predict(X)

    def anomaly(self, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        scores, source_out = self.det.anomaly(X)
        local_out = self.local.score_samples(self.det._anomaly_input(X)) < self.local_threshold
        return scores, source_out & local_out
