"""How long does a site's model of normal stay valid? (docs/PREREGISTRATION_CONFIRM.md, C3)

  python scripts/cadence_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --old <29 Oct pilot sessions> --recent $(cat data/study_sessions.txt) \
      --study data/sensor/study_wifi_20261101.json [--portable] --results docs/results/cadence.md

The repair (30 triaged local flows plus the exemplar envelope) is fitted on local traffic of two ages and scored
on the same later evening (1 November): the 29 October pilot (three days old) and the 30 October evening (two days
old). The pilot holds far fewer flows, so the 30 October pool is also subsampled to the pilot's size (three draws
per seed); age is compared at equal size. Five seeds; per-block sign test on seed-averaged rates. Aggregates only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from preregistered_tests import sign_test  # noqa: E402
from real_network_eval import load_session, score_blocks, study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset, score_attacks  # noqa: E402

from ids.data import feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope  # noqa: E402
from ids.repair import triage_sample  # noqa: E402

DRAWS = 3


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--old", nargs="+", required=True)
    ap.add_argument("--recent", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--results", default="docs/results/cadence.md")
    ap.add_argument("--equal-size", choices=["recent", "both"], default="recent",
                    help="recent: subsample the recent pool to the old pool's size (C3); both: subsample both pools "
                         "to the smaller size, three draws each (PREREGISTRATION_DAY3.md, H3)")
    ap.add_argument("--old-label", default="old pool")
    ap.add_argument("--recent-label", default="recent pool")
    ap.add_argument("--eval-label", default="1 November")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]
    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    old = pd.concat([load_session(Path(s), feats) for s in args.old], ignore_index=True)
    recent = pd.concat([load_session(Path(s), feats) for s in args.recent], ignore_index=True)
    blocks = [b for b in (load_session(p, feats) for p in study_sessions(args.study)) if len(b)]
    rows = []

    def repaired(base, pool: pd.DataFrame, labels: pd.DataFrame, seed: int):
        triaged, _ = triage_sample(base, pool, feats, args.service_flows, seed)
        det = fit_detector(pd.concat([src["train"], labels, triaged]), src["val"], feats, args.model)
        return ExemplarEnvelope(det, pool[feats])

    for seed in seeds:
        labels = few_shot(tgt, args.k, 1000, seed)
        base = fit_detector(pd.concat([src["train"], labels]), src["val"], feats, args.model)
        rng = np.random.default_rng(seed)
        if args.equal_size == "recent":  # C3, as committed
            pools = {"few-shot (no repair)": None, "3 days old (29 Oct pilot)": old, "2 days old (30 Oct, full)": recent}
            pools.update({f"2 days old (30 Oct, {len(old)}-flow draw {i + 1})":
                          recent.iloc[rng.choice(len(recent), size=len(old), replace=False)] for i in range(DRAWS)})
        else:
            n = min(len(old), len(recent))
            pools = {"few-shot (no repair)": None, f"{args.old_label}, full": old, f"{args.recent_label}, full": recent}
            for i in range(DRAWS):
                pools[f"{args.old_label}, {n}-flow draw {i + 1}"] = old.iloc[rng.choice(len(old), size=n, replace=False)]
                pools[f"{args.recent_label}, {n}-flow draw {i + 1}"] = recent.iloc[rng.choice(len(recent), size=n, replace=False)]
        for name, pool in pools.items():
            det = base if pool is None else repaired(base, pool, labels, seed)
            rn = score_blocks(det, blocks, feats)
            rows.append({"pool": name, "seed": seed, "pool_flows": 0 if pool is None else int(len(pool)),
                         "rate": rn["rate"], "block_rates": rn["block_rates"],
                         "detection": score_attacks(det, tgt["test"], feats)["macro_detection"]})
            print(f"{name} seed {seed}: rate {rn['rate']:.3f}", flush=True)

    def blocks_of(match: str) -> np.ndarray:
        return np.mean([r["block_rates"] for r in rows if match in r["pool"]], axis=0)

    if args.equal_size == "recent":
        old_b, size_b = blocks_of("3 days old"), blocks_of("-flow draw")
    else:
        old_b = np.mean([r["block_rates"] for r in rows if r["pool"].startswith(args.old_label) and "draw" in r["pool"]], axis=0)
        size_b = np.mean([r["block_rates"] for r in rows if r["pool"].startswith(args.recent_label) and "draw" in r["pool"]], axis=0)
    res = {"generated": time.strftime("%Y-%m-%d"), "features": len(feats), "portable": args.portable, "seeds": seeds,
           "equal_size": args.equal_size, "labels": [args.old_label, args.recent_label, args.eval_label],
           "old_flows": int(len(old)), "recent_flows": int(len(recent)), "rows": rows,
           "primary": {"old_vs_equal_size_recent": sign_test(old_b, size_b),
                       "old_mean": float(old_b.mean()), "recent_equal_size_mean": float(size_b.mean())},
           "minutes": (time.perf_counter() - t0) / 60}
    p = res["primary"]
    if args.equal_size == "both":  # mean per-block difference with a 95% block-bootstrap interval
        diff = old_b - size_b
        boot = np.random.default_rng(42).choice(diff, size=(2000, len(diff)), replace=True).mean(axis=1)
        p["mean_difference"], p["difference_ci"] = float(diff.mean()), [float(np.percentile(boot, 2.5)),
                                                                          float(np.percentile(boot, 97.5))]
    p["decay"] = p["old_vs_equal_size_recent"]["p"] < 0.05 and p["old_mean"] > p["recent_equal_size_mean"]
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(to_markdown(res))


def to_markdown(res: dict) -> str:
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    names = list(dict.fromkeys(r["pool"] for r in res["rows"]))
    if res.get("equal_size") == "both":
        return day3_markdown(res, feats, names)
    L = ["# Refit cadence: does the site's model of normal age? (C3)", "",
         f"Generated on {res['generated']}. {res['features']} features ({feats}); seeds {', '.join(map(str, res['seeds']))}. "
         "Every condition is scored on the 1 November evening. Rule in docs/PREREGISTRATION_CONFIRM.md.", "",
         "| Local traffic used for the repair | Flows | Alerts, 1 Nov (mean of seeds) | Benchmark detection |", "|---|---|---|---|"]
    for n in names:
        rs = [r for r in res["rows"] if r["pool"] == n]
        L.append(f"| {n} | {rs[0]['pool_flows']:,} | {np.mean([r['rate'] for r in rs]):.1%} | "
                 f"{np.mean([r['detection'] for r in rs]):.3f} |")
    p, t = res["primary"], res["primary"]["old_vs_equal_size_recent"]
    L += ["", f"**Primary (C3):** 3-day-old pool {p['old_mean']:.2%} vs 2-day-old pool of equal size "
          f"{p['recent_equal_size_mean']:.2%} (block means); old higher in {t['higher']}, lower in {t['lower']}, "
          f"ties {t['ties']}, sign test p = {t['p']:.3f}: "
          + ("**decay detected**." if p["decay"] else "**no decay detected** at this age difference."), "",
          "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


def day3_markdown(res: dict, feats: str, names: list[str]) -> str:
    old, recent, ev = res["labels"]
    L = [f"# Refit cadence: {old} versus {recent} (H3)", "",
         f"Generated on {res['generated']}. {res['features']} features ({feats}); seeds {', '.join(map(str, res['seeds']))}. "
         f"Every condition is scored on {ev}. Both pools subsampled to the smaller size, three draws each. "
         "Rule in docs/PREREGISTRATION_DAY3.md.", "",
         f"| Local traffic used for the repair | Flows | Alerts, {ev} (mean of seeds) | Benchmark detection |",
         "|---|---|---|---|"]
    for n in names:
        rs = [r for r in res["rows"] if r["pool"] == n]
        L.append(f"| {n} | {rs[0]['pool_flows']:,} | {np.mean([r['rate'] for r in rs]):.1%} | "
                 f"{np.mean([r['detection'] for r in rs]):.3f} |")
    p, t = res["primary"], res["primary"]["old_vs_equal_size_recent"]
    lo, hi = p["difference_ci"]
    L += ["", f"**Primary (H3):** {old} {p['old_mean']:.2%} vs {recent} {p['recent_equal_size_mean']:.2%} at equal size "
          f"(block means); difference {p['mean_difference']:+.2%} (95% block bootstrap {lo:+.2%} to {hi:+.2%}); old higher "
          f"in {t['higher']}, lower in {t['lower']}, ties {t['ties']}, sign test p = {t['p']:.3f}: "
          + ("**decay detected**." if p["decay"] else "**no decay detected** at this age."), "",
          "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
