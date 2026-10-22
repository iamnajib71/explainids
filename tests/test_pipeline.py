import numpy as np
import pandas as pd
import pytest

from ids.alerts import aggregate, build_alerts
from ids.data import BENIGN, LABEL_COL, add_sessions, canonical_label, clean, feature_columns, session_split
from ids.evaluate import benign_fpr, report
from ids.explain import Explainer, rank_agreement
from ids.models import Detector
from ids.privacy import pseudonymise
from ids.synthetic import make_flows
from ids.threat import context_for


@pytest.fixture(scope="module")
def flows():
    return clean(make_flows(120))


@pytest.mark.parametrize("raw,expected", [
    ("BENIGN", BENIGN), ("SSH-Patator", "SSH-BruteForce"), ("SSH-Bruteforce", "SSH-BruteForce"),
    ("DoS Hulk - Attempted", BENIGN), ("DDOS attack-LOIC-UDP", "DDoS-UDP"), ("DDoS attacks-LOIC-HTTP", "DDoS-HTTP"),
    ("Brute Force -Web", "Web-BruteForce"), ("SQL Injection", "Web-SQLInjection"), ("PortScan", "PortScan"),
])
def test_canonical_labels(raw, expected):
    assert canonical_label(raw) == expected


def test_attempted_can_be_kept_as_attack():
    assert canonical_label("DoS Hulk - Attempted", attempted_as_benign=False) == "DoS-Hulk"


def test_clean_removes_inf_nan_and_duplicates():
    df = make_flows(10)
    df.loc[0, "Flow Bytes/s"] = np.inf
    df = pd.concat([df, df.iloc[[1]]], ignore_index=True)
    out = clean(df)
    assert np.isfinite(out[feature_columns(out)].to_numpy()).all()
    assert len(out) == len(df) - 2


def test_identifiers_are_not_features(flows):
    feats = feature_columns(flows)
    for col in ("Src IP", "Dst IP", "Flow ID", "Timestamp", LABEL_COL):
        assert col not in feats


def test_session_split_has_no_session_leakage(flows):
    train, val, test = session_split(add_sessions(flows))
    assert set(train.session).isdisjoint(test.session)
    assert set(train.session).isdisjoint(val.session)
    assert len(train) + len(val) + len(test) == len(flows)


@pytest.mark.parametrize("name", ["rf", "xgb", "lgbm"])
def test_models_learn_synthetic_classes(flows, name):
    X, y = flows[feature_columns(flows)], flows[LABEL_COL]
    det = Detector(name).fit(X, y)
    r = report(y, det.predict(X))
    assert r["macro"]["f1"] > 0.9
    assert r["benign_fpr"] < 0.05


def test_benign_fpr():
    assert benign_fpr(["BENIGN", "BENIGN", "Bot"], ["BENIGN", "Bot", "Bot"]) == 0.5


def test_anomaly_threshold_controls_benign_fpr(flows):
    X, y = flows[feature_columns(flows)], flows[LABEL_COL]
    det = Detector("rf").fit(X, y).fit_anomaly(X[y == BENIGN])
    det.tune_anomaly_threshold(X[y == BENIGN], target_fpr=0.05)
    _, flagged = det.anomaly(X[y == BENIGN])
    assert flagged.mean() <= 0.06


def test_shap_explanations_and_alerts(flows):
    X, y = flows[feature_columns(flows)], flows[LABEL_COL]
    det = Detector("lgbm").fit(X, y)
    sample = flows[flows[LABEL_COL] != BENIGN].head(5)
    pred = det.predict(sample)
    expl = Explainer(det).top_features(sample, list(pred), k=3)
    assert len(expl) == 5 and len(expl[0]) == 3
    alerts = build_alerts(sample, pred, det.predict_proba(sample), explanations=expl)
    assert all(a["attack"]["technique"] for a in alerts)
    assert all(len(a["summary"].split()) <= 30 for a in alerts)
    assert aggregate(alerts)


def test_threat_mapping_is_candidate_or_unmapped():
    assert context_for("SSH-BruteForce").technique_id == "T1110"
    assert context_for("DDoS-UDP").technique_id == "T1498"
    assert context_for("Web-XSS").technique == "unmapped"
    assert context_for(BENIGN, is_outlier=True).technique.startswith("unmapped")


def test_pseudonymise_is_keyed_and_stable():
    df = make_flows(2)
    a = pseudonymise(df, key=b"k1")
    b = pseudonymise(df, key=b"k1")
    c = pseudonymise(df, key=b"k2")
    assert (a["Src IP"] == b["Src IP"]).all()
    assert (a["Src IP"] != c["Src IP"]).all()
    assert not a["Src IP"].str.contains(r"\d+\.\d+\.\d+\.\d+").any()


def test_rank_agreement():
    assert rank_agreement(["a", "b"], ["a", "b"]) == 1.0
    assert rank_agreement(["a", "b"], ["c", "d"]) == 0.0
