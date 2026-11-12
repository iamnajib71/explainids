import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

from ids.data import BENIGN, LABEL_COL
from ids.envelope import LocalNormal

spec = importlib.util.spec_from_file_location(
    "attack_retention_eval", Path(__file__).resolve().parents[1] / "scripts/attack_retention_eval.py")
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)

FEATS = ["a", "b"]


def frame(values, label=BENIGN):
    df = pd.DataFrame(values, columns=FEATS, dtype=float)
    df[LABEL_COL] = label
    return df


def test_morph_endpoints():
    normal = frame([[0, 0], [100, 100], [1000, 1000]])
    attacks = frame([[90, 95], [5, 1]], "PortScan")
    env = LocalNormal(FEATS, normal)
    assert np.allclose(ar.morph(attacks, normal, FEATS, env, 0.0)[FEATS], attacks[FEATS])
    end = ar.morph(attacks, normal, FEATS, env, 1.0)[FEATS].to_numpy()
    assert np.allclose(end, [[100, 100], [0, 0]])                       # each reaches its own nearest normal
    assert np.allclose(ar.morph(attacks, normal, FEATS, env, 0.5)[FEATS].to_numpy()[0], [95, 97.5])


def test_contaminate_adds_unlabelled_attacks():
    pool, attacks = frame([[1, 1]] * 5), frame([[9, 9]] * 4, "SYN-Burst")
    assert len(ar.contaminate(pool, attacks, 0, 1)) == 5
    assert len(ar.contaminate(pool, attacks, 3, 1)) == 8
    assert len(ar.contaminate(pool, attacks, 99, 1)) == 9                # capped at the attacks available


def test_mislabel_keeps_size_and_marks_attacks_benign():
    triaged, attacks = frame([[1, 1]] * 30), frame([[9, 9]] * 20, "SSH-BruteForce")
    out = ar.mislabel(triaged, attacks, 10, 1)
    assert len(out) == 30
    assert (out[LABEL_COL] == BENIGN).all()
    assert int((out["a"] == 9).sum()) == 10


class Always:
    def __init__(self, hit):
        self.hit = hit

    def predict(self, X):
        return np.where(self.hit[: len(X)], "PortScan", BENIGN)

    def anomaly(self, X):
        return np.zeros(len(X)), np.zeros(len(X), dtype=bool)


def test_score_lab_separates_attacks_and_benign():
    lab = pd.concat([frame([[1, 1]] * 2, "PortScan"), frame([[2, 2]] * 2, "SYN-Burst"), frame([[0, 0]] * 2)],
                    ignore_index=True)
    out = ar.score_lab(Always(np.array([1, 1, 1, 0, 1, 0], dtype=bool)), lab, FEATS)
    assert (out["attacks"], out["caught"]) == (4, 3)
    assert out["per_class"] == {"PortScan": 1.0, "SYN-Burst": 0.5}
    assert out["benign_fpr"] == 0.5


def test_mislabel_marks_dismissed_attacks():
    out = ar.mislabel(frame([[1, 1]] * 30), frame([[9, 9]] * 20, "PortScan"), 3, 1)
    assert int(out["dismissed_attack"].sum()) == 3
    assert not ar.mislabel(frame([[1, 1]] * 30), frame([[9, 9]] * 20, "PortScan"), 0, 1)["dismissed_attack"].any()


def test_gate_keeps_only_flows_near_site_normal():
    env = LocalNormal(FEATS, frame([[1, 1], [2, 2], [3, 3], [4, 4]]))
    dismissed = frame([[2, 2], [5000, 9000]])
    assert ar.gate(dismissed, env)[FEATS].to_numpy().tolist() == [[2.0, 2.0]]


class Split:
    def predict(self, X):
        return np.array(["PortScan", BENIGN, BENIGN, BENIGN])[: len(X)]

    def anomaly(self, X):
        return np.zeros(len(X)), np.array([True, True, False, False])[: len(X)]


def test_anomaly_only_share():
    assert ar.anomaly_only_share(Split(), frame([[0, 0]] * 4)) == 0.5
