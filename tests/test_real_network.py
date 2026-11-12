import json

import numpy as np
import pandas as pd

from ids.repair import local_sample
from scripts.real_network_eval import block_bootstrap, study_sessions


def test_local_sample_has_exact_budget_and_covers_services():
    pool = pd.DataFrame({"Dst Port": [443] * 50 + [53] * 20 + [1900] * 5 + list(range(40000, 40010))})
    got = local_sample(pool, 30, seed=42)
    assert len(got) == 30 and got.index.is_unique
    assert {443, 53, 1900} <= set(got["Dst Port"])


def test_local_sample_never_exceeds_the_pool():
    pool = pd.DataFrame({"Dst Port": [443, 443, 80]})
    assert len(local_sample(pool, 30, seed=1)) == 3


def test_block_bootstrap_brackets_the_pooled_rate():
    alerts, flows = np.array([1, 5, 2, 0]), np.array([100, 100, 100, 100])
    lo, hi = block_bootstrap(alerts, flows)
    assert lo <= alerts.sum() / flows.sum() <= hi and hi <= 0.05


def test_block_bootstrap_needs_two_blocks():
    assert np.isnan(block_bootstrap(np.array([1]), np.array([10]))[0])


def test_study_keeps_only_validated_blocks(tmp_path):
    (tmp_path / "good").mkdir()
    (tmp_path / "good" / "validated.csv").write_text("x\n1\n")
    (tmp_path / "nocsv").mkdir()
    record = {"blocks": [{"returncode": 0, "session": "good"}, {"returncode": 1, "session": "bad"},
                         {"returncode": 0, "session": "nocsv"}, {"returncode": 0, "session": None}]}
    study = tmp_path / "study.json"
    study.write_text(json.dumps(record))
    assert [p.name for p in study_sessions(study)] == ["good"]


def test_service_concentration_separates_collapsed_from_scattered():
    from scripts.real_network_eval import service_concentration
    flows = {"1900": 20, "443": 200, "53": 50, "9999": 2}
    alerts = {"1900": 20, "443": 4, "9999": 2}
    s = service_concentration(flows, alerts)
    assert s["collapsed_services"] == ["1900"]          # 9999 has too few flows to judge
    assert s["share_in_collapsed"] == 20 / 26
    assert s["services_clean"] == 1 and s["services_partial"] == 1


class _StubDetector:
    """Calls every flow on port 1900 an attack; nothing anomalous."""
    def predict(self, X):
        return np.where(X["Dst Port"] == 1900, "PortScan", "BENIGN")

    def anomaly(self, X):
        return np.zeros(len(X)), np.zeros(len(X), dtype=bool)


def test_triage_prefers_confirmed_alerts_then_tops_up():
    from ids.repair import triage_sample
    pool = pd.DataFrame({"Dst Port": [1900] * 4 + [443] * 40})
    got, confirmed = triage_sample(_StubDetector(), pool, ["Dst Port"], 10, seed=42)
    assert confirmed == 4 and len(got) == 10 and got.index.is_unique
    assert (got["Dst Port"] == 1900).sum() == 4


def test_two_envelope_only_flags_what_both_envelopes_reject():
    from ids.envelope import TwoEnvelope

    class Source:
        features = ["a"]
        def _anomaly_input(self, X):
            return X[["a"]]
        def predict(self, X):
            return np.array(["BENIGN"] * len(X))
        def anomaly(self, X):                       # source envelope: anything above 10 is unusual
            return -X["a"].to_numpy(), (X["a"] > 10).to_numpy()

    rng = np.random.default_rng(0)
    local = pd.DataFrame({"a": rng.normal(100, 5, 500)})   # this site's normal is large transfers
    two = TwoEnvelope(Source(), local)
    X = pd.DataFrame({"a": [5.0, 100.0, 10_000.0]})
    assert two.anomaly(X)[1].tolist() == [False, False, True]


def test_exemplar_envelope_vetoes_a_service_seen_once():
    from ids.envelope import ExemplarEnvelope

    class Source:
        features = ["a", "b"]
        def predict(self, X):
            return np.array(["BENIGN"] * len(X))
        def anomaly(self, X):                       # benchmark envelope: big transfers are unusual
            return -X["a"].to_numpy(), (X["a"] > 1e4).to_numpy()

    rng = np.random.default_rng(0)
    local = pd.DataFrame({"a": rng.uniform(100, 1000, 300), "b": rng.uniform(1, 10, 300)})
    local.loc[len(local)] = {"a": 5e6, "b": 5.0}          # one confirmed bulk download
    env = ExemplarEnvelope(Source(), local)
    X = pd.DataFrame({"a": [500.0, 5.1e6, 5e9], "b": [5.0, 5.0, 5.0]})
    assert env.anomaly(X)[1].tolist() == [False, False, True]


def test_uncertainty_sample_takes_least_confident_flows():
    from ids.repair import uncertainty_sample

    class Det:
        def predict_proba(self, X):
            p = X["c"].to_numpy()
            return np.column_stack([p, 1 - p])

    pool = pd.DataFrame({"c": [0.99, 0.5, 0.9, 0.55, 0.6]})
    got = uncertainty_sample(Det(), pool, ["c"], 2)
    assert sorted(got["c"].tolist()) == [0.5, 0.55]


def test_local_refit_learns_the_site_normal():
    from ids.envelope import LocalRefit

    class Source:
        features = ["a"]
        def _anomaly_input(self, X):
            return X[["a"]]
        def predict(self, X):
            return np.array(["BENIGN"] * len(X))

    rng = np.random.default_rng(0)
    src = pd.DataFrame({"a": rng.normal(0, 1, 500)})
    local = pd.DataFrame({"a": rng.normal(100, 1, 300)})
    refit = LocalRefit(Source(), src, local)
    X = pd.DataFrame({"a": [100.0, 1e6]})
    assert refit.anomaly(X)[1].tolist() == [False, True]
