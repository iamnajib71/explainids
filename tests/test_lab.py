import pandas as pd
import pytest

from ids.data import BENIGN, LABEL_COL, clean, feature_columns
from ids.models import Detector
from ids.synthetic import make_flows
from scripts.evaluate_lab import evaluate
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
