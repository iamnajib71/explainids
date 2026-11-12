import json
import sys

import numpy as np
import pandas as pd
import pytest

from ids.data import BENIGN, LABEL_COL, clean, temporal_split
from ids.synthetic import make_flows
from scripts import multi_env_eval as evaluation
from scripts.multi_env_eval import few_shot, json_safe, matched_pair, score


def test_few_shot_takes_oracle_balanced_rows_from_earlier_class_partitions():
    df = clean(make_flows(120))
    train, _, test = temporal_split(df)
    shots = few_shot({"train": train}, k=5, benign=20, seed=42)
    counts = shots[LABEL_COL].value_counts()
    assert all(counts[c] == 5 for c in counts.index if c != BENIGN)
    assert counts[BENIGN] == 20
    assert set(shots.index) <= set(train.index) and not set(shots.index) & set(test.index)


def dataset(name, offset):
    rows = pd.DataFrame({
        "feature": np.arange(26) + offset,
        "Timestamp": pd.date_range("2026-10-01", periods=26, freq="min").astype(str),
        LABEL_COL: [BENIGN] * 12 + ["PortScan"] * 6 + [BENIGN, "PortScan"] * 4,
    }, index=np.arange(26) + offset)
    return {"name": name, "train": rows.iloc[:18], "val": rows.iloc[18:22], "test": rows.iloc[22:]}


def test_matched_pair_shares_exact_target_rows_without_source_or_extra_calibration():
    source, target = dataset("source", 0), dataset("target", 1000)
    mixed, control = matched_pair(source, target, k=3, benign=10, seed=42)
    pd.testing.assert_frame_equal(mixed["calibration"], control["calibration"])
    fit_ids, cal_ids = set(control["train"].index), set(control["calibration"].index)
    local = few_shot(target, k=3, benign=10, seed=42)
    assert fit_ids | cal_ids == set(local.index)
    assert not fit_ids & cal_ids
    assert not (fit_ids | cal_ids) & set(target["val"].index)
    assert not (fit_ids | cal_ids) & set(target["test"].index)
    assert not fit_ids & set(source["train"].index)
    assert set(mixed["train"].index) == set(source["train"].index) | fit_ids
    assert control["train"][LABEL_COL].eq(BENIGN).sum() == 8
    assert len(control["calibration"]) == 2
    left, right = mixed["label_accounting"], control["label_accounting"]
    for key in ("target_sample_identity_sha256", "target_fit_identity_sha256", "target_calibration_identity_sha256"):
        assert left[key] == right[key]
    assert right["target_annotation_rows"] == 13
    assert right["source_training_rows"] == right["source_validation_rows_inspected"] == right["extra_target_validation_rows_inspected"] == 0
    assert set(control["calibration"][LABEL_COL]) == {BENIGN}


def test_matched_pair_rejects_insufficient_benign_budget_and_overlapping_partitions():
    source, target = dataset("source", 0), dataset("target", 1000)
    with pytest.raises(ValueError, match="at least two"):
        matched_pair(source, target, k=2, benign=1, seed=42)
    overlap = {**target, "test": target["train"].iloc[:2]}
    with pytest.raises(ValueError, match="disjoint"):
        matched_pair(source, overlap, k=2, benign=6, seed=42)


def test_load_preserves_row_identity_when_training_is_capped(monkeypatch):
    raw = clean(make_flows(120))
    monkeypatch.setattr(pd, "read_parquet", lambda _: raw)
    loaded = evaluation.load("fixture.parquet", cap=5)
    assert len(loaded["train"]) < len(raw)
    assert not set(loaded["train"].index) & set(loaded["test"].index)
    assert not set(loaded["train"].index) & set(loaded["val"].index)


class FixedDetector:
    features = ["feature"]
    classes = [BENIGN, "PortScan", "SSH-BruteForce"]
    iforest = object()

    def predict(self, X):
        return np.array([BENIGN if int(value) % 2 else "PortScan" for value in X.feature])

    def anomaly(self, X):
        return np.zeros(len(X)), X.feature.to_numpy() == 5


def test_complete_metrics_agree_with_confusion_and_unknown_detection():
    flows = pd.DataFrame({"feature": [1, 2, 4, 3, 6, 5],
                          LABEL_COL: [BENIGN, BENIGN, "PortScan", "PortScan", "SYN-Burst", "SYN-Burst"]})
    result = score(FixedDetector(), flows, ["feature"], [BENIGN, "PortScan"])
    attr = result["attribution"]
    cm = np.asarray(attr["confusion"])
    assert cm.sum() == result["flows"] == 6
    assert result["classifier"]["tp"] == 2
    assert result["anomaly"]["tp"] == 1
    assert result["with_anomaly"]["tp"] == 3
    metrics = {row["class"]: row for row in attr["per_class"]}
    for i, label in enumerate(attr["labels"]):
        correct, true_count, predicted_count = cm[i, i], cm[i].sum(), cm[:, i].sum()
        precision = correct / predicted_count if predicted_count else 0
        recall = correct / true_count if true_count else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        assert metrics[label]["support"] == true_count
        assert metrics[label]["precision"] == pytest.approx(precision)
        assert metrics[label]["recall"] == pytest.approx(recall)
        assert metrics[label]["f1"] == pytest.approx(f1)
    assert result["per_class"]["SYN-Burst"] == 1.0
    assert metrics["SYN-Burst"]["f1"] == 0
    assert not metrics["SYN-Burst"]["seen_in_training"]
    expected = np.mean([row["f1"] for row in metrics.values() if row["support"]])
    assert attr["macro_observed"]["f1"] == pytest.approx(expected)


def test_benign_metrics_are_strict_json_null_and_invalid_rows_are_counted():
    flows = pd.DataFrame({"feature": [1, 2, np.inf], LABEL_COL: [BENIGN] * 3})
    result = json_safe(score(FixedDetector(), flows, ["feature"], [BENIGN]))
    encoded = json.dumps(result, allow_nan=False)
    assert "NaN" not in encoded
    assert result["flows"] == 2 and result["dropped_invalid"] == 1
    assert result["recall"] is result["f1"] is result["macro_detection"] is None
    assert result["with_anomaly"]["fp"] == 1 and result["fpr"] == 0.5
    with pytest.raises(ValueError, match="missing model features"):
        score(FixedDetector(), flows.drop(columns="feature"), ["feature"], [BENIGN])


def test_cli_matches_controls_and_keeps_multiple_benign_profiles_separate(tmp_path, monkeypatch):
    inputs = {"a": dataset("source", 0), "b": dataset("target", 1000)}
    monkeypatch.setattr(evaluation, "load", lambda name, cap: inputs[name])
    calls = []

    def fake_fit(train, val, feats, model):
        calls.append((train.copy(), val.copy()))
        return FixedDetector()

    monkeypatch.setattr(evaluation, "fit", fake_fit)
    benign_paths = []
    for i in range(2):
        path = tmp_path / f"benign{i}.csv"
        pd.DataFrame({"feature": [1, 2], LABEL_COL: [BENIGN] * 2}).to_csv(path, index=False)
        benign_paths.append(str(path))
    out = tmp_path / "matched.md"
    monkeypatch.setattr(sys, "argv", ["multi_env_eval", "a", "b", "--target-only", "--shots", "2", "--seeds", "42",
                                      "--local-benign", "6", "--results", str(out), "--benign-eval", *benign_paths])
    evaluation.main()
    result = json.loads(out.with_suffix(".json").read_text(), parse_constant=lambda value: pytest.fail(value))
    assert len(result["runs"]) == 7
    for a, b in ((3, 4), (5, 6)):
        mixed, target = result["runs"][a], result["runs"][b]
        assert mixed["label_accounting"]["target_sample_identity_sha256"] == target["label_accounting"]["target_sample_identity_sha256"]
        assert target["label_accounting"]["source_training_rows"] == 0
        pd.testing.assert_frame_equal(calls[a][1], calls[b][1])
        assert not set(calls[b][0].index) & set(calls[b][1].index)
    assert len(result["benign_evaluation_inputs"]) == 2
    for run in result["runs"]:
        assert sum(key.startswith("benign:") for key in run["tests"]) == 2
    markdown = out.read_text()
    assert "Confusion matrix" in markdown and "Support" in markdown and "N/A" in markdown


def test_benign_profile_rejects_attack_labels_before_any_model_is_fitted(tmp_path, monkeypatch):
    inputs = {"a": dataset("source", 0), "b": dataset("target", 1000)}
    monkeypatch.setattr(evaluation, "load", lambda name, cap: inputs[name])

    def forbidden_fit(*args, **kwargs):
        pytest.fail("invalid benign profile must fail before model fitting")

    monkeypatch.setattr(evaluation, "fit", forbidden_fit)
    path = tmp_path / "contains_attack.csv"
    pd.DataFrame({"feature": [1, 2], LABEL_COL: [BENIGN, "PortScan"]}).to_csv(path, index=False)
    monkeypatch.setattr(sys, "argv", ["multi_env_eval", "a", "b", "--benign-eval", str(path)])
    with pytest.raises(SystemExit) as exc:
        evaluation.main()
    assert exc.value.code == 2
