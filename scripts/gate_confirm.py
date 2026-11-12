"""Confirmation of the dismissal gate on fresh dismissals (docs/PREREGISTRATION_CONFIRM.md, C1).

  python scripts/gate_confirm.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab-runs <poison replicate> <held replicate> <held replicate> --fit-sessions <day-1 sessions> \
      --study data/sensor/study_wifi_20261101.json --seeds 5,6,7,8,9 [--portable] --results docs/results/gate_confirm.md

The exploratory result (attack_retention_eval.py, R5) used replicate A's attacks as the wrongly dismissed flows and
seeds 42, 1-4. Here a different replicate supplies them and new seeds draw the labels, triage sets and dismissed
flows, so no dismissal from the exploratory run recurs. Aggregates only.
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
from attack_retention_eval import gate, load_lab_run, mislabel, score_lab  # noqa: E402
from real_network_eval import load_session, score_blocks, study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset  # noqa: E402

from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope, LocalNormal  # noqa: E402
from ids.repair import triage_sample  # noqa: E402

DISMISSED = [3, 10]


def verdict(rows: list[dict], k: int) -> dict:
    """Rule C1 for one dismissal count: effect replicates, gate restores, gate keeps legitimate flows."""
    by = lambda arm: {r["seed"]: r for r in rows if r["arm"] == arm and r["dismissed"] == k}  # noqa: E731
    clean = {s: r["recall"] for s, r in by("clean").items()}
    ungated, gated = by("ungated"), by("gated")
    drop = float(np.mean([clean[s] - ungated[s]["recall"] for s in clean]))
    restored = sum(abs(gated[s]["recall"] - clean[s]) <= 0.02 for s in clean)
    kept = float(np.mean([g["legit_kept"] / g["legit_offered"] for g in gated.values()]))
    return {"mean_drop_ungated": drop, "seeds_restored": restored, "seeds": len(clean), "legit_kept": kept,
            "effect_replicates": drop >= 0.10 if k == 3 else None,
            "confirmed": restored >= 4 and kept >= 0.90 and (drop >= 0.10 if k == 3 else True)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--lab-runs", nargs=3, type=Path, required=True)
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="5,6,7,8,9")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--results", default="docs/results/gate_confirm.md")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]
    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    lab = pd.concat([load_lab_run(p, feats) for p in args.lab_runs], ignore_index=True)
    poison_run = args.lab_runs[0].name
    poison = lab[(lab["replicate"] == poison_run) & (lab[LABEL_COL] != BENIGN)]
    held = lab[lab["replicate"] != poison_run]
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    blocks = [b for b in (load_session(p, feats) for p in study_sessions(args.study)) if len(b)]
    site = LocalNormal(feats, fit_pool)
    rows = []

    def record(arm: str, det, seed: int, k: int, **meta) -> None:
        lab_score = score_lab(ExemplarEnvelope(det, fit_pool[feats]), held, feats)
        rows.append({"arm": arm, "seed": seed, "dismissed": k, "recall": lab_score["recall"],
                     "per_class": lab_score["per_class"],
                     "real_network_rate": score_blocks(ExemplarEnvelope(det, fit_pool[feats]), blocks, feats)["rate"],
                     **meta})
        print(f"{arm} k={k} seed {seed}: recall {lab_score['recall']:.3f} {meta}", flush=True)

    for seed in seeds:
        labels = few_shot(tgt, args.k, 1000, seed)
        base = fit_detector(pd.concat([src["train"], labels]), src["val"], feats, args.model)
        triaged, _ = triage_sample(base, fit_pool, feats, args.service_flows, seed)
        clean = fit_detector(pd.concat([src["train"], labels, triaged]), src["val"], feats, args.model)
        for k in DISMISSED:
            record("clean", clean, seed, k)
            wrong = mislabel(triaged, poison, k, seed)
            record("ungated", fit_detector(pd.concat([src["train"], labels, wrong]), src["val"], feats, args.model),
                   seed, k)
            kept = gate(wrong, site)
            record("gated", fit_detector(pd.concat([src["train"], labels, kept]), src["val"], feats, args.model),
                   seed, k, attacks_kept=int(kept["dismissed_attack"].sum()),
                   legit_kept=int((~kept["dismissed_attack"]).sum()), legit_offered=int((~wrong["dismissed_attack"]).sum()))

    res = {"generated": time.strftime("%Y-%m-%d"), "features": len(feats), "portable": args.portable,
           "seeds": seeds, "poison_replicate": poison_run, "poison_attacks": int(len(poison)),
           "held_attacks": int((held[LABEL_COL] != BENIGN).sum()), "rows": rows,
           "verdicts": {str(k): verdict(rows, k) for k in DISMISSED}, "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(to_markdown(res))


def to_markdown(res: dict) -> str:
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    L = ["# Confirmation: gating dismissals by the site envelope (C1)", "",
         f"Generated on {res['generated']}. {res['features']} features ({feats}); seeds {', '.join(map(str, res['seeds']))}; "
         f"wrongly dismissed attacks drawn from {res['poison_replicate']} ({res['poison_attacks']} attacks), recall "
         f"measured on the other two replicates ({res['held_attacks']} attacks). Rule in docs/PREREGISTRATION_CONFIRM.md.", "",
         "| Dismissed attacks | Clean | Ungated | Gated | Attacks passing the gate | Legitimate dismissals kept | Seeds restored (±2 pts) | Verdict |",
         "|---|---|---|---|---|---|---|---|"]
    for k, v in res["verdicts"].items():
        rs = [r for r in res["rows"] if r["dismissed"] == int(k)]
        m = lambda arm, key="recall": np.mean([r[key] for r in rs if r["arm"] == arm])  # noqa: E731
        L.append(f"| {k} | {m('clean'):.1%} | {m('ungated'):.1%} | {m('gated'):.1%} | {m('gated', 'attacks_kept'):.1f} | "
                 f"{v['legit_kept']:.0%} | {v['seeds_restored']}/{v['seeds']} | {'**confirmed**' if v['confirmed'] else '**not confirmed**'} |")
    L += ["", "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
