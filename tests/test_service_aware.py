import numpy as np
import pandas as pd
import pytest

from ids.data import BENIGN, LABEL_COL
from scripts.service_aware_eval import load_profile, score_benign, service_key, split_profile

PORTS = [80] * 20 + [443] * 8 + [21] * 6 + [20] * 6 + [22] * 6


def profile(n_feature_noise: float = 0.0) -> pd.DataFrame:
    rng = np.random.default_rng(0)
    return pd.DataFrame({
        "Dst Port": PORTS,
        "Flow Duration": rng.normal(100, 5 + n_feature_noise, len(PORTS)),
        LABEL_COL: [BENIGN] * len(PORTS),
    })


def test_split_is_disjoint_and_covers_every_service():
    fit, held = split_profile(profile(), n_fit=10, seed=42)
    assert not set(fit.index) & set(held.index)
    assert len(fit) + len(held) == len(profile())
    assert set(service_key(fit)) == set(service_key(profile()))   # no service left unrepresented
    assert all(len(g) >= 1 for _, g in held.groupby(service_key(held)))


def test_zero_service_flows_trains_on_nothing_and_holds_everything():
    fit, held = split_profile(profile(), n_fit=0, seed=42)
    assert fit.empty and len(held) == len(profile())


def test_split_never_consumes_an_entire_service_group():
    fit, held = split_profile(profile(), n_fit=46, seed=7)      # asking for everything
    for port, group in held.groupby(service_key(held)):
        assert len(group) >= 1, f"service {port} fully consumed by the fit split"


def test_load_profile_rejects_a_capture_containing_attacks(tmp_path):
    bad = profile().assign(**{LABEL_COL: [BENIGN] * 45 + ["PortScan"]})
    path = tmp_path / "mixed.csv"
    bad.to_csv(path, index=False)
    with pytest.raises(ValueError, match="all-benign"):
        load_profile(str(path), ["Dst Port", "Flow Duration"])


def test_score_benign_reports_rate_interval_and_assigned_classes():
    class Detector:
        features = ["Dst Port", "Flow Duration"]
        iforest = object()

        def predict(self, X):
            return np.where(X["Dst Port"] == 20, "PortScan", BENIGN)

        def anomaly(self, X):
            return np.zeros(len(X)), np.zeros(len(X), dtype=bool)

    result = score_benign(Detector(), profile(), ["Dst Port", "Flow Duration"])
    assert result["false_alerts"] == 6 and result["flows"] == 46
    assert result["fpr"] == pytest.approx(6 / 46)
    lo, hi = result["fpr_ci"]
    assert lo < result["fpr"] < hi
    assert result["called"] == {"PortScan": 6}
    assert result["by_service_port"]["20"] == 1.0 and result["by_service_port"]["80"] == 0.0


def test_empty_profile_reports_null_rate_rather_than_a_false_zero():
    result = score_benign(object(), profile().iloc[:0], ["Dst Port"])
    assert result["flows"] == 0 and result["fpr"] is None
