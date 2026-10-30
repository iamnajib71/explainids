import numpy as np
import pandas as pd

from scripts.envelope_audit import audit, envelope


class _Det:
    def predict(self, X):
        return np.array(["BENIGN"] * len(X))

    def anomaly(self, X):
        return None, (X["bytes"] > 1000).to_numpy()


def test_anomaly_flows_are_the_ones_outside_the_envelope():
    benign = pd.DataFrame({"bytes": np.arange(1000.0), "pkts": np.arange(1000.0)})
    lo, hi = envelope(benign)
    X = pd.DataFrame({"bytes": [10.0, 500.0, 50_000.0], "pkts": [5.0, 6.0, 7.0]})
    res = audit(_Det(), X, lo, hi)
    assert res["anomaly_only"]["flows"] == 1 and res["quiet"]["flows"] == 2
    assert res["anomaly_only"]["feature_rates"]["bytes"] == 1.0
    assert res["quiet"]["feature_rates"]["bytes"] == 0.0
