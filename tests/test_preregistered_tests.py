import importlib.util
from pathlib import Path

import numpy as np

spec = importlib.util.spec_from_file_location(
    "preregistered_tests", Path(__file__).resolve().parents[1] / "scripts/preregistered_tests.py")
pt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)


def test_sign_test_all_lower():
    t = pt.sign_test(np.zeros(12), np.ones(12))
    assert (t["lower"], t["higher"], t["ties"]) == (12, 0, 0)
    assert abs(t["p"] - 2 / 2 ** 12) < 1e-12


def test_sign_test_drops_ties():
    t = pt.sign_test(np.array([0, 1, 2]), np.array([1, 1, 1]))
    assert (t["lower"], t["higher"], t["ties"]) == (1, 1, 1)
    assert t["p"] == 1.0


def test_sign_test_all_ties():
    assert pt.sign_test(np.ones(4), np.ones(4))["p"] == 1.0


def test_evaluate_averages_seeds_per_block():
    def run(config, seed, rates, det):
        return {"config": config, "seed": seed, "real_network": {"block_rates": rates},
                "target_test": {"macro_detection": det}}
    runs = []
    for seed in (1, 2):
        runs += [run(pt.FEW_SHOT, seed, [0.06, 0.05, 0.07], 0.96),
                 run(pt.REPAIR, seed, [0.02, 0.01, 0.03], 0.95 + seed / 100),
                 run(pt.LAB, seed, [0.07, 0.04, 0.07], 0.96)]
        runs += [run(c, seed, [0.03, 0.03, 0.03], 0.96) for c in pt.EXPLORATORY]
    out = pt.evaluate({"runs": runs})
    assert out["repair"]["lower"] == 3
    assert abs(out["detection_change"] - 0.005) < 1e-9
    assert (out["lab"]["lower"], out["lab"]["higher"], out["lab"]["ties"]) == (1, 1, 1)
