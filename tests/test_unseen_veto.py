import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

from ids.data import BENIGN, LABEL_COL

spec = importlib.util.spec_from_file_location(
    "unseen_veto_eval", Path(__file__).resolve().parents[1] / "scripts/unseen_veto_eval.py")
uv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uv)


class Fixed:
    def __init__(self, clf, anom):
        self.clf, self.anom = np.array(clf), np.array(anom)

    def predict(self, X):
        return np.where(self.clf, "Bot", BENIGN)

    def anomaly(self, X):
        return np.zeros(len(X)), self.anom


def test_veto_counts_only_counts_anomaly_only_flows():
    X = pd.DataFrame({"a": range(5)})
    base = Fixed([1, 0, 0, 0, 0], [1, 1, 1, 0, 0])
    variant = Fixed([1, 0, 0, 0, 0], [0, 1, 0, 0, 0])
    c = uv.veto_counts(base, variant, X)
    assert (c["classifier"], c["anomaly_only"], c["vetoed"]) == (1, 2, 1)
    assert (c["caught"], c["caught_variant"]) == (3, 2)


def test_without_drops_class_from_every_split():
    df = pd.DataFrame({LABEL_COL: ["Bot", BENIGN, "PortScan"]})
    out = uv.without({"name": "x", "train": df, "test": df}, "Bot")
    assert "Bot" not in set(out["train"][LABEL_COL]) and out["name"] == "x"
