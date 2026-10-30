"""Two-envelope anomaly rule: unusual for the benchmark's normal *and* for the site's normal."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import NearestNeighbors

from ids import SEED
from ids.models import signed_log


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


class ExemplarEnvelope:
    """Two-envelope rule whose local envelope is exemplar-based: a flow is usual for the site if it lies
    near *any* known-normal local flow.

    An isolation forest is density-based, so a service the site has shown only once or twice still looks
    isolated and is not vetoed. A nearest-neighbour envelope needs only one example per service, which
    matches a repair budget of one or two flows per service. Features are signed-log transformed and
    scaled by the local median and IQR; the threshold is the (1 - budget) quantile of each local flow's
    leave-one-out distance to its nearest neighbour, so at most `budget` of the site's own normal traffic
    would count as unusual.
    """

    def __init__(self, det, local: pd.DataFrame, budget: float = 0.01):
        self.det, self.features = det, det.features
        Z = np.asarray(signed_log(local[self.features]), dtype=float)
        self.center = np.median(Z, axis=0)
        iqr = np.subtract(*np.percentile(Z, [75, 25], axis=0))
        self.scale = np.where(iqr > 0, iqr, 1.0)
        self.Z = (Z - self.center) / self.scale
        self.nn = NearestNeighbors(n_neighbors=2).fit(self.Z)
        loo = self.nn.kneighbors(self.Z)[0][:, 1]
        self.threshold = float(np.quantile(loo, 1 - budget))

    def _transform(self, X: pd.DataFrame) -> np.ndarray:
        return (np.asarray(signed_log(X[self.features]), dtype=float) - self.center) / self.scale

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.det.predict(X)

    def anomaly(self, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        scores, source_out = self.det.anomaly(X)
        out = np.zeros(len(X), dtype=bool)
        idx = np.flatnonzero(source_out)
        if len(idx):
            dist = self.nn.kneighbors(self._transform(X.iloc[idx]), n_neighbors=1)[0][:, 0]
            out[idx] = dist > self.threshold
        return scores, out
