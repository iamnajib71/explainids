import numpy as np
import pandas as pd
import pytest

from ids.data import BENIGN, LABEL_COL, clean, feature_columns
from ids.models import Detector
from ids.synthetic import make_flows
from scripts.evaluate_lab import evaluate, to_markdown
from scripts.label_lab_flows import label_flows

ATTACKER, VICTIM, OTHER = "192.168.56.10", "192.168.56.20", "192.168.56.30"


def lab_flows():
    return pd.DataFrame({
        "Src IP": [ATTACKER, VICTIM, ATTACKER, OTHER, ATTACKER],
        "Dst IP": [VICTIM, ATTACKER, VICTIM, VICTIM, VICTIM],
        "Timestamp": ["2026-10-31 10:00:05", "2026-10-31 10:00:30", "2026-10-31 10:20:00",
                      "2026-10-31 10:00:10", "2026-10-31 10:40:01"],
    })


def schedule(**over):
    rows = [{"scenario": "S1", "label": "SSH brute force", "attacker_ip": ATTACKER, "victim_ip": VICTIM,
             "start": "2026-10-31 10:00:00", "end": "2026-10-31 10:01:00"},
            {"scenario": "S5", "label": "SYN-Flood", "attacker_ip": ATTACKER, "victim_ip": VICTIM,
             "start": "2026-10-31 10:40:00", "end": "2026-10-31 10:41:00"}]
    return pd.DataFrame([{**r, **over} for r in rows])


def test_labels_both_directions_inside_window_only():
    out = label_flows(lab_flows(), schedule())
    assert out[LABEL_COL].tolist() == ["SSH-BruteForce", "SSH-BruteForce", BENIGN, BENIGN, "SYN-Flood"]


def test_pad_widens_window_for_clock_skew():
    flows = lab_flows().assign(Timestamp="2026-10-31 10:01:02")
    assert label_flows(flows.head(1), schedule(), pad_s=0)[LABEL_COL].iat[0] == BENIGN
    assert label_flows(flows.head(1), schedule(), pad_s=5)[LABEL_COL].iat[0] == "SSH-BruteForce"


def test_overlapping_scenarios_are_rejected():
    bad = schedule()
    bad.loc[1, ["start", "end"]] = ["2026-10-31 10:00:00", "2026-10-31 10:01:00"]
    with pytest.raises(ValueError, match="overlaps"):
        label_flows(lab_flows(), bad)


def test_evaluate_counts_unseen_class_as_caught_by_any_alert():
    train = clean(make_flows(80))
    feats = feature_columns(train)
    det = Detector("rf").fit(train[feats], train[LABEL_COL]).fit_anomaly(train[train[LABEL_COL] == BENIGN][feats])
    det.tune_anomaly_threshold(train[train[LABEL_COL] == BENIGN][feats])
    lab = clean(make_flows(20, seed=3))
    lab.loc[lab[LABEL_COL] == "PortScan", LABEL_COL] = "SYN-Flood"   # a class the model never saw
    res = evaluate(det, lab)
    by_class = {s["class"]: s for s in res["per_scenario"]}
    assert not by_class["SYN-Flood"]["seen_in_training"]
    assert 0 <= res["with_anomaly"]["recall"] <= 1 and res["flows"] == len(lab)
    assert "SYN-Flood" not in res["macro_known"] and set(res["macro_known"]) == {"precision", "recall", "f1"}


def test_per_class_attribution_matches_confusion_without_claiming_unknown_labels():
    class FrozenDetector:
        features = ["flow_feature"]
        classes = [BENIGN, "PortScan", "SSH-BruteForce"]
        iforest = object()

        def predict(self, X):
            return np.array([BENIGN, "PortScan", "PortScan", BENIGN, "PortScan", BENIGN])

        def anomaly(self, X):
            # The final unknown attack is detected only by the anomaly layer.
            return np.zeros(len(X)), np.array([False, False, False, False, False, True])

    flows = pd.DataFrame({"flow_feature": range(6),
                          LABEL_COL: [BENIGN, BENIGN, "PortScan", "PortScan", "SYN-Flood", "SYN-Flood"]})
    res = evaluate(FrozenDetector(), flows)
    metrics = {row["class"]: row for row in res["per_class"]}
    confusion = np.array(res["confusion"])
    assert list(metrics) == res["labels"]
    assert confusion.sum() == res["flows"] == sum(row["support"] for row in metrics.values())
    for i, label in enumerate(res["labels"]):
        row = metrics[label]
        true_count, predicted_count, correct = confusion[i].sum(), confusion[:, i].sum(), confusion[i, i]
        precision = correct / predicted_count if predicted_count else 0
        recall = correct / true_count if true_count else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        assert row["support"] == true_count
        assert row["precision"] == pytest.approx(precision)
        assert row["recall"] == pytest.approx(recall)
        assert row["f1"] == pytest.approx(f1)
    assert metrics["SSH-BruteForce"]["support"] == 0  # Include every evaluated label.
    observed = [row for row in metrics.values() if row["support"] > 0]
    for metric in ("precision", "recall", "f1"):
        assert res["macro_observed"][metric] == pytest.approx(np.mean([row[metric] for row in observed]))
    assert not metrics["SYN-Flood"]["seen_in_training"]
    assert metrics["SYN-Flood"]["recall"] == metrics["SYN-Flood"]["f1"] == 0
    scenarios = {row["class"]: row for row in res["per_scenario"]}
    assert scenarios["SYN-Flood"]["classifier"] == 0.5
    assert scenarios["SYN-Flood"]["with_anomaly"] == 1.0
    rendered = to_markdown({**res, "generated": "2026-10-25", "model": "frozen test detector"}, "test")
    assert "| SYN-Flood | 0.000 | 0.000 | 0.000 | 2 | no |" in rendered
    assert "without being correctly attributed" in rendered


def test_alert_burden_carries_interval_and_projection():
    from scripts.evaluate_lab import alert_burden
    b = alert_burden(fp=0, benign=40, hours=0.05, benign_per_hour=10_000)
    assert b["per_10k"] == 0 and b["per_10k_ci"][1] > 800        # 0/40 still allows ~876 per 10k
    assert b["projected_per_hour"] == 0 and b["projected_per_hour_ci"][1] > 800
    assert alert_burden(fp=5, benign=10_000, hours=2, benign_per_hour=None)["per_capture_hour"] == 2.5
