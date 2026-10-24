"""Model zoo, training with class weighting, and validation-only threshold tuning."""
from __future__ import annotations

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from . import SEED
from .data import BENIGN


def make_classifier(name: str):
    if name == "rf":
        return RandomForestClassifier(n_estimators=200, n_jobs=-1, class_weight="balanced_subsample", random_state=SEED)
    if name == "xgb":
        return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, tree_method="hist",
                             n_jobs=-1, random_state=SEED, eval_metric="mlogloss")
    if name == "lgbm":
        return LGBMClassifier(n_estimators=300, num_leaves=63, class_weight="balanced", random_state=SEED, verbose=-1)
    raise ValueError(f"unknown model {name!r}")


def signed_log(X: pd.DataFrame) -> np.ndarray:
    """sign(x) * log1p(|x|): tames heavy-tailed flow features (keeps CICFlowMeter's -1 sentinels distinct)."""
    arr = np.asarray(X, dtype=np.float64)
    return np.sign(arr) * np.log1p(np.abs(arr))


class Detector:
    """A fitted multi-class classifier plus an optional benign-only Isolation Forest."""

    def __init__(self, name: str = "lgbm", anomaly_log: bool = False):
        self.name = name
        self.anomaly_log = anomaly_log
        self.model = make_classifier(name)
        self.encoder = LabelEncoder()
        self.features: list[str] = []
        self.iforest: IsolationForest | None = None
        self.anomaly_threshold: float | None = None

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "Detector":
        self.features = list(X.columns)
        y_enc = self.encoder.fit_transform(y)
        if self.name == "xgb":  # XGBoost has no class_weight; use balanced sample weights instead
            self.model.fit(X, y_enc, sample_weight=compute_sample_weight("balanced", y_enc))
        else:
            self.model.fit(X, y_enc)
        return self

    def fit_anomaly(self, X_benign: pd.DataFrame) -> "Detector":
        self.iforest = IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1).fit(self._anomaly_input(X_benign))
        return self

    def _anomaly_input(self, X: pd.DataFrame):
        X = X[self.features]
        return signed_log(X) if getattr(self, "anomaly_log", False) else X  # older pickles lack the flag

    def tune_anomaly_threshold(self, X_val_benign: pd.DataFrame, target_fpr: float = 0.01) -> float:
        """Pick the score below which a benign validation flow is flagged at most `target_fpr` of the time."""
        scores = self.iforest.score_samples(self._anomaly_input(X_val_benign))
        self.anomaly_threshold = float(np.quantile(scores, target_fpr))
        return self.anomaly_threshold

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.encoder.inverse_transform(self.model.predict(X[self.features]))

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(X[self.features])

    def anomaly(self, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        scores = self.iforest.score_samples(self._anomaly_input(X))
        return scores, scores < self.anomaly_threshold

    @property
    def classes(self) -> list[str]:
        return list(self.encoder.classes_)

    @property
    def benign_index(self) -> int:
        return self.classes.index(BENIGN)
