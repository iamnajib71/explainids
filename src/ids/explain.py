"""Per-alert SHAP explanations (TreeSHAP) and a simple explanation-stability check."""
from __future__ import annotations

import numpy as np
import pandas as pd
import shap


class Explainer:
    def __init__(self, detector):
        self.detector = detector
        self._explainer = shap.TreeExplainer(detector.model)

    def top_features(self, X: pd.DataFrame, predicted: list[str], k: int = 5) -> list[list[dict]]:
        """For each row, the k features pushing hardest towards its predicted class."""
        values = self._explainer.shap_values(X[self.detector.features])
        classes = self.detector.classes
        out = []
        for i, label in enumerate(predicted):
            cls = classes.index(label)
            row = _row_values(values, i, cls)
            order = np.argsort(-np.abs(row))[:k]
            out.append([{"feature": self.detector.features[j], "value": float(X.iloc[i][self.detector.features[j]]),
                         "contribution": float(row[j])} for j in order])
        return out


def _row_values(values, i: int, cls: int) -> np.ndarray:
    if isinstance(values, list):          # older SHAP: list of (n, f) arrays per class
        return np.asarray(values[cls][i])
    arr = np.asarray(values)
    return arr[i, :, cls] if arr.ndim == 3 else arr[i]


def rank_agreement(a: list[str], b: list[str]) -> float:
    """Jaccard overlap of two top-k feature lists (used to compare explanations across seeds)."""
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else 1.0
