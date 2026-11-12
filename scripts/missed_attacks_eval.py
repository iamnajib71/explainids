"""Why does every variant miss FTP brute force and incomplete HTTP probes in the lab, and can a few labels fix it?

Usage:
  python scripts/missed_attacks_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab-runs <replicate A> <B> <C> --benign-profiles <two 330-flow benign profiles> \
      --fit-sessions $(cat data/study_sessions.txt) --study data/sensor/study_wifi_20261101.json \
      [--portable] --results docs/results/missed_attacks.md

`attack_retention_eval.py` found two lab attack types that every detector variant misses. Two explanations
predict different things, so both are tested:

  D  Feature blindness. If the 83 flow features cannot tell these attacks from normal sessions on the same
     service, no training data can help. Test: inside the lab only, a random forest trained on two replicates'
     attacks plus lab benign flows is scored on the third replicate (leave one replicate out). Also reported:
     what the deployed model predicts for these flows, and how often a flow's nearest training neighbour is
     benign.
  F  Missing training data. If the features can see them, a few labelled examples should. Test: k = 0, 3 or 12
     labelled flows of each missed type from replicate A are added to the deployed recipe (few-shot + 30 triaged
     local flows + exemplar envelope); recall is measured on replicates B and C only.

Rules, fixed in this file before the first run (exploratory: not pre-registered elsewhere):
  * Features *can see* a type if leave-one-replicate-out recall is at least 0.8 at a benign false-positive rate of
    at most 5% on the held-out replicate's benign flows and both benign profiles.
  * Labels *fix* a type if, at k = 12, mean held-out recall over seeds is at least 0.8, while the false-alert rate
    on the two benign service profiles rises by at most 2 points and on the real-network evening by at most 0.5.
Outputs hold aggregates only; accuracy is never reported (rule 4).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import NearestNeighbors

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_retention_eval import flagged, load_lab_run  # noqa: E402
from real_network_eval import load_session, score_blocks, study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset, score_attacks  # noqa: E402

from ids import SEED  # noqa: E402
from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope  # noqa: E402
from ids.models import signed_log  # noqa: E402
from ids.repair import triage_sample  # noqa: E402

MISSED = ["FTP-BruteForce", "Incomplete-HTTP-Probe"]
LABEL_BUDGETS = [0, 3, 12]


def separability(lab: pd.DataFrame, profiles: pd.DataFrame, feats: list[str], cls: str) -> dict:
    """Leave-one-replicate-out: can a lab-only model tell this attack type from lab benign flows?"""
    recalls, fprs = [], []
    for held in sorted(lab["replicate"].unique()):
        train = lab[(lab["replicate"] != held) & lab[LABEL_COL].isin([cls, BENIGN])]
        test = lab[(lab["replicate"] == held) & lab[LABEL_COL].isin([cls, BENIGN])]
        rf = RandomForestClassifier(n_estimators=200, random_state=SEED, class_weight="balanced")
        rf.fit(signed_log(train[feats]), train[LABEL_COL] == cls)
        attack = (test[LABEL_COL] == cls).to_numpy()
        pred = rf.predict(signed_log(test[feats]))
        benign_pred = np.concatenate([pred[~attack], rf.predict(signed_log(profiles[feats]))])
        recalls.append(float(pred[attack].mean()))
        fprs.append(float(benign_pred.mean()))
    return {"recall": float(np.mean(recalls)), "benign_fpr": float(np.mean(fprs)),
            "per_replicate_recall": recalls}


def nearest_training_label(train: pd.DataFrame, X: pd.DataFrame, feats: list[str]) -> dict:
    """Share of flows whose nearest training flow (standardised signed-log space) carries each label."""
    Z = np.asarray(signed_log(train[feats]), dtype=float)
    mu, sd = Z.mean(axis=0), Z.std(axis=0) + 1e-9
    nn = NearestNeighbors(n_neighbors=1).fit((Z - mu) / sd)
    idx = nn.kneighbors((np.asarray(signed_log(X[feats]), dtype=float) - mu) / sd)[1][:, 0]
    return train[LABEL_COL].iloc[idx].value_counts(normalize=True).round(3).to_dict()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--lab-runs", nargs=3, type=Path, required=True, help="replicates A (label source), B, C")
    ap.add_argument("--benign-profiles", nargs="+", type=Path, required=True)
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--results", default="docs/results/missed_attacks.md")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    lab = pd.concat([load_lab_run(p, feats) for p in args.lab_runs], ignore_index=True)
    profiles = pd.concat([load_lab_run(p, feats) for p in args.benign_profiles], ignore_index=True)
    rep_a = args.lab_runs[0].name
    held = lab[lab["replicate"] != rep_a]
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    blocks = [b for b in (load_session(p, feats) for p in study_sessions(args.study)) if len(b)]

    diagnosis = {cls: {"separability": separability(lab, profiles, feats, cls),
                       "nearest_source_training_label": nearest_training_label(
                           src["train"], lab[lab[LABEL_COL] == cls], feats),
                       "in_source_training": bool((src["train"][LABEL_COL] == cls).any()),
                       "in_target_training": bool((tgt["train"][LABEL_COL] == cls).any())}
                 for cls in MISSED}
    print(json.dumps(diagnosis), flush=True)

    rows = []
    for seed in seeds:
        labels = few_shot(tgt, args.k, 1000, seed)
        base = fit_detector(pd.concat([src["train"], labels]), src["val"], feats, args.model)
        triaged, _ = triage_sample(base, fit_pool, feats, args.service_flows, seed)
        for k in LABEL_BUDGETS:
            extra = [lab[(lab["replicate"] == rep_a) & (lab[LABEL_COL] == c)].sample(k, random_state=seed)
                     for c in MISSED] if k else []
            rep = fit_detector(pd.concat([src["train"], labels, triaged, *extra]), src["val"], feats, args.model)
            det = ExemplarEnvelope(rep, fit_pool[feats])
            hit = flagged(det, held[feats])
            per_class = pd.Series(hit, index=held.index).groupby(held[LABEL_COL]).mean().round(4).to_dict()
            if k == 0 and seed == seeds[0]:
                for cls in MISSED:
                    X = lab[lab[LABEL_COL] == cls][feats]
                    diagnosis[cls]["deployed_predictions"] = pd.Series(det.predict(X)).value_counts().to_dict()
            rows.append({"seed": seed, "k": k, "held_out_recall": per_class,
                         "profile_fpr": float(flagged(det, profiles[feats]).mean()),
                         "real_network_rate": score_blocks(det, blocks, feats)["rate"],
                         "benchmark_detection": score_attacks(det, tgt["test"], feats)["macro_detection"]})
            r = rows[-1]
            print(f"seed {seed} k {k}: " + ", ".join(f"{c} {r['held_out_recall'].get(c, 0):.2f}" for c in MISSED)
                  + f" | profiles {r['profile_fpr']:.3f} | real-net {r['real_network_rate']:.3f}", flush=True)

    res = {"generated": time.strftime("%Y-%m-%d"), "features": len(feats), "portable": args.portable,
           "seeds": seeds, "label_source": rep_a, "held_out_attacks": {c: int((held[LABEL_COL] == c).sum()) for c in MISSED},
           "profile_flows": len(profiles), "diagnosis": diagnosis, "rows": rows,
           "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(f"results in {out}")


def to_markdown(res: dict) -> str:
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    L = ["# The two lab attack types every variant misses", "",
         f"Generated on {res['generated']}. {res['features']} features ({feats}); seeds "
         f"{', '.join(map(str, res['seeds']))}; labelled examples from {res['label_source']}, recall on the other two "
         f"replicates ({', '.join(f'{c}: {n}' for c, n in res['held_out_attacks'].items())} flows); "
         f"{res['profile_flows']} benign service-profile flows. Rules in the script docstring.", "",
         "## D. Can the features see them?", "",
         "| Attack type | In 2017 / 2018 training | Lab-only recall (leave one replicate out) | Lab-only benign FPR | "
         "Nearest training flow | Deployed model predicts | Verdict |", "|---|---|---|---|---|---|---|"]
    for cls, d in res["diagnosis"].items():
        s = d["separability"]
        sees = s["recall"] >= 0.8 and s["benign_fpr"] <= 0.05
        near = ", ".join(f"{k} {v:.0%}" for k, v in d["nearest_source_training_label"].items())
        pred = ", ".join(f"{k} {v}" for k, v in d.get("deployed_predictions", {}).items())
        L.append(f"| {cls} | {'yes' if d['in_source_training'] else 'no'} / {'yes' if d['in_target_training'] else 'no'} | "
                 f"{s['recall']:.2f} | {s['benign_fpr']:.1%} | {near} | {pred} | "
                 f"{'**features can see it**' if sees else '**features cannot separate it**'} |")
    L += ["", "## F. Do a few labels fix it?", "",
          "| Labelled flows per type (k) | " + " | ".join(f"{c} recall" for c in MISSED)
          + " | Benign profile false alerts | Real-network alerts | Benchmark detection |",
          "|---|" + "---|" * (len(MISSED) + 3)]
    df = pd.DataFrame(res["rows"])
    means = {}
    for k, g in df.groupby("k"):
        rec = {c: np.mean([r.get(c, 0.0) for r in g["held_out_recall"]]) for c in MISSED}
        means[k] = (rec, g["profile_fpr"].mean(), g["real_network_rate"].mean(), g["benchmark_detection"].mean())
        L.append(f"| {k} | " + " | ".join(f"{rec[c]:.2f}" for c in MISSED)
                 + f" | {means[k][1]:.1%} | {means[k][2]:.1%} | {means[k][3]:.3f} |")
    top, base = means[max(means)], means[0]
    L.append("")
    for c in MISSED:
        fixed = top[0][c] >= 0.8 and top[1] - base[1] <= 0.02 and top[2] - base[2] <= 0.005
        L.append(f"**{c}:** k = {max(means)} gives recall {top[0][c]:.2f} (from {base[0][c]:.2f}); profile false alerts "
                 f"{base[1]:.1%} → {top[1]:.1%}, real-network {base[2]:.1%} → {top[2]:.1%}: "
                 + ("**fixed by labels** under the rule." if fixed else "**not fixed** under the rule."))
        L.append("")
    L += ["Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
