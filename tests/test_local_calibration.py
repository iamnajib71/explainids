import numpy as np
import pandas as pd

from ids.data import BENIGN, LABEL_COL, clean, feature_columns
from ids.models import Detector
from ids.synthetic import make_flows
from scripts.local_calibration_eval import calibrate, summarise


def test_summarise_balances_classes_and_counts_false_alarms():
    y = pd.Series([BENIGN] * 4 + ["A"] * 4 + ["B"])
    flagged = np.array([True, False, False, False] + [True] * 4 + [False])
    s = summarise(y, flagged)
    assert s["fpr"] == 0.25 and s["false_alarms_per_10k"] == 2500
    assert s["recall"] == 0.8                       # 4 of 5 attack flows
    assert s["macro_detection"] == 0.5              # class A 100%, class B 0%: each class counts once
    assert set(s["per_class"]) == {"A", "B"}


def test_calibration_thresholds_respect_the_local_false_alarm_budget():
    flows = clean(make_flows(150))
    feats = feature_columns(flows)
    det = Detector("rf").fit(flows[feats], flows[LABEL_COL])
    local = flows[flows[LABEL_COL] == BENIGN]
    cal = calibrate(det, local, feats, budget=0.1, seed=42)
    assert cal["if_half"] <= cal["if_full"] and cal["pb_half"] <= cal["pb_full"]
    hold = local.sample(frac=0.3, random_state=42)
    from ids.models import signed_log
    flagged = cal["iforest"].score_samples(signed_log(hold[feats])) < cal["if_full"]
    assert flagged.mean() <= 0.12                   # about the 10% budget on the hold-out it was set on
