"""Fast synthetic checks of training-seed SHAP stability and conditional comparisons."""
from copy import deepcopy
import json

import numpy as np
import pytest
from threadpoolctl import threadpool_limits

from ids import models
from ids.data import BENIGN, LABEL_COL, dedup_global, feature_columns, stratified_sample, temporal_split
from ids.synthetic import make_flows
from scripts.shap_stability_eval import attack_sample, compare_runs, explain_run, fit, global_spearman


@pytest.fixture(scope="module")
def experiment():
    # Limit test compute, while retaining real Detector training, bagging and TreeSHAP.
    original = models.make_classifier
    with pytest.MonkeyPatch.context() as patch, threadpool_limits(limits=1):
        def small_classifier(name):
            return original(name).set_params(n_estimators=24, num_leaves=7, min_child_samples=5, n_jobs=1)

        patch.setattr(models, "make_classifier", small_classifier)
        df = dedup_global(make_flows(100))
        train, _, test = temporal_split(df)
        train = stratified_sample(train, 65, seed=42)
        explained = attack_sample(test, 24)
        feats = feature_columns(train)
        detectors = [fit(train, feats, "lgbm", seed) for seed in [42, 1, 42]]
        runs = [explain_run(det, test, explained, seed, k=5)
                for det, seed in zip(detectors, [42, 1, 42])]
    return detectors, runs, test, explained


def test_different_seeds_train_different_bagged_models(experiment):
    detectors, runs, _, explained = experiment
    a, b = detectors[:2]
    for det in (a, b):
        params = det.model.get_params()
        assert params["bagging_fraction"] == params["feature_fraction"] == 0.8
        assert params["bagging_freq"] == 1
    assert not np.array_equal(a.predict_proba(explained), b.predict_proba(explained))
    result = compare_runs(runs[:2])
    assert result["local"]["overall"]["count"] > 0
    assert 0 <= result["local"]["overall"]["median"] <= 1


def test_same_seed_is_exactly_reproducible(experiment):
    detectors, runs, _, explained = experiment
    assert np.array_equal(detectors[0].predict_proba(explained), detectors[2].predict_proba(explained))
    result = compare_runs([runs[0], runs[2]])
    assert result["local"]["overall"]["count"] == len(explained)
    assert result["local"]["overall"]["median"] == 1.0
    assert result["local"]["overall"]["p10"] == 1.0
    assert result["pairs"][0]["global_spearman"] == 1.0
    assert result["pairs"][0]["global_top10_jaccard"] == 1.0
    assert result["local"]["skipped_prediction_changes"] == 0


def test_prediction_changes_are_skipped_and_counted(experiment):
    _, runs, _, explained = experiment
    other = deepcopy(runs[0])
    other["seed"] = 7
    for i in range(3):
        other["predicted"][i] = "OtherAttack"
        other["local_top"][i] = ["must not be compared"]
    result = compare_runs([runs[0], other])
    assert result["local"]["skipped_prediction_changes"] == 3
    assert result["pairs"][0]["skipped_prediction_changes"] == 3
    assert result["local"]["total_pairs"] == len(explained)
    assert result["local"]["overall"]["count"] == len(explained) - 3
    assert result["local"]["overall"]["median"] == 1.0
    assert sum(s["count"] for s in result["local"]["per_predicted_class"].values()) == len(explained) - 3


def test_all_disagreements_have_no_fabricated_stability(experiment):
    _, runs, _, explained = experiment
    other = deepcopy(runs[0])
    other["predicted"] = ["OtherAttack"] * len(explained)
    result = compare_runs([runs[0], other])
    assert result["local"]["skipped_prediction_changes"] == len(explained)
    assert result["local"]["overall"] == {"count": 0, "median": None, "p10": None}


def test_attack_sample_is_fixed_total_from_test_only(experiment):
    _, _, test, explained = experiment
    assert len(explained) == 24
    assert BENIGN not in set(explained[LABEL_COL])
    assert set(explained.index) <= set(test.index)
    assert explained.equals(attack_sample(test, 24))
    assert len(attack_sample(test, 10000)) == (test[LABEL_COL] != BENIGN).sum()
    with pytest.raises(ValueError, match="no attack"):
        attack_sample(test[test[LABEL_COL] == BENIGN], 10)


def test_global_ranks_use_union_and_missing_rank_16():
    # Union a,b,c has ranks [1,2,16] and [16,1,2], giving rho=-0.5.
    assert global_spearman(["a", "b"], ["b", "c"]) == pytest.approx(-0.5)
    assert global_spearman(["a"], ["a"]) == 1.0
    assert global_spearman([], []) is None


def test_cli_writes_markdown_and_json(experiment, monkeypatch, tmp_path):
    from scripts import shap_stability_eval as script

    detectors, _, test, _ = experiment
    parquet = tmp_path / "synthetic.parquet"
    make_flows(100).to_parquet(parquet)
    output = tmp_path / "results" / "stability.md"
    # Real training is covered above; reuse it to keep the CLI/output check fast.
    monkeypatch.setattr(script, "fit", lambda train, feats, model, seed: detectors[0])
    monkeypatch.setattr("sys.argv", ["shap_stability_eval.py", str(parquet), "--seeds", "42,42",
                                   "--flows", "24", "--cap", "65", "--results", str(output)])
    with threadpool_limits(limits=1):
        script.main()
    result = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    markdown = output.read_text(encoding="utf-8")
    assert result["explained_flows"] == 24
    assert result["test_rows"] == len(test)
    assert result["pairs"][0]["global_spearman"] == 1.0
    assert "bagging_fraction=0.8" in markdown
    assert "Prediction changes skipped" in markdown
    assert "Confusion matrix" in markdown
    assert "accuracy" not in markdown.lower()
    for run in result["runs"]:
        assert set(run["performance"]) == {"macro", "benign_fpr", "per_class", "confusion"}
