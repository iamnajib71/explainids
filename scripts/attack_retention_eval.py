"""Does the local repair make the detector easier to fool? Four security tests of the deployment recipe.

Usage:
  python scripts/attack_retention_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab-runs data/lab/run_20261025T050509Z data/lab/run_20261025T050628Z data/lab/run_20261025T051149Z \
      --fit-sessions $(cat data/study_sessions.txt) --study data/sensor/study_wifi_20261101.json \
      [--portable] --results docs/results/attack_retention.md

The repair (30 triaged local flows plus a local model of normal fitted on an earlier day) cut false alerts on
a real network. A reviewer's first question is what it costs in attacks. The home network was never attacked
(ethics rule 5), so attacks come from two places that never touch it: the benchmark's held-out 2018 test, and
three bounded attack replicates captured in the isolated lab (port scan, SYN burst, SSH and FTP brute force,
incomplete HTTP probes; 792 flows). Each flow is scored independently, so scoring the lab attacks with a
detector fitted for the home network is the same as injecting them into its traffic.

Tests and decision rules, fixed in this file before the first run:

  R1 retention   Lab-attack and benchmark detection of every repaired variant against few-shot. The repair
                 *retains* detection if pooled lab-attack recall (mean over seeds) falls by at most 2 points;
                 per-class recall is reported so a loss concentrated in one attack type is visible.
  R2 poisoning   The local model of normal is fitted on traffic nobody labelled. Lab attacks from replicate A
                 are mixed into that fit pool (0 to all 252 flows), and separately an analyst wrongly dismisses
                 3 or 10 of them as benign during triage. Recall is measured on replicates B and C only, so no
                 evaluated attack flow was ever seen in fitting. Reported as a dose-response curve.
  R3 budget      Fit pool subsampled to 100, 300 and 1,000 flows: the smallest pool whose false-alert rate on
                 the evaluation evening is within 0.5 points of the full pool's is the data a site needs.
  R4 evasion     Each lab attack flow is moved in feature space toward its nearest local normal flow,
                 x' = (1 - a) x + a n, a = 0 ... 1. The envelope opens a new evasion path if, at some a, the
                 repaired detector with the envelope flags more than 5 points fewer morphed attacks than the
                 same detector with the benchmark anomaly layer. Feature interpolation is not a realisable
                 attack; it is a geometric stress test of where the veto sits relative to the classifier.

Added after a one-seed smoke run (rules above unchanged; these are labelled exploratory in the output):

  Vetoable share  The fraction of caught attacks caught by the anomaly layer alone. A veto on anomaly alerts can
                  remove at most this much detection, so it bounds what R1 and R2 can show.
  R5 gated triage The smoke run showed that a few attacks wrongly dismissed in triage blind the classifier to
                  their type. Mitigation: a dismissed alert enters the repair set only if it resembles the site's
                  earlier normal traffic (inside the local envelope). Compared with ungated triage at 3 and 10
                  dismissed attacks; the gate must also leave the real-network false-alert rate unchanged.

Outputs hold aggregates only. Accuracy is never reported (rule 4).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from real_network_eval import load_session, score_blocks, study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset, score_attacks  # noqa: E402

from ids import SEED  # noqa: E402
from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope, LocalNormal, LocalRefit, TwoEnvelope  # noqa: E402
from ids.evaluate import wilson_interval  # noqa: E402
from ids.models import signed_log  # noqa: E402
from ids.repair import triage_sample  # noqa: E402
from ids.scoring import align_columns  # noqa: E402

ALPHAS = [0.0, 0.2, 0.4, 0.6, 0.8, 0.9, 1.0]
POOL_SIZES = [100, 300, 1000]
DISMISSED = [3, 10]


def load_lab_run(folder: Path, feats: list[str]) -> pd.DataFrame:
    """A labelled lab replicate (attack and benign flows) aligned to the model schema; invalid rows dropped."""
    raw = pd.read_csv(folder / "flows_labelled.csv", low_memory=False)
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise ValueError(f"{folder.name}: {len(missing)} features missing, e.g. {missing[:5]}")
    numeric = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    out = aligned.loc[valid, [LABEL_COL]].copy()
    out[feats] = numeric.loc[valid]
    out["replicate"] = folder.name
    return out.reset_index(drop=True)


def flagged(det, X: pd.DataFrame) -> np.ndarray:
    return np.asarray((det.predict(X) != BENIGN) | det.anomaly(X)[1])


def anomaly_only_share(det, X: pd.DataFrame) -> float | None:
    """Of the flows flagged, the share flagged by the anomaly layer alone (the most a veto could remove)."""
    clf = np.asarray(det.predict(X) != BENIGN)
    anom = np.asarray(det.anomaly(X)[1])
    caught = clf | anom
    return float((anom & ~clf).sum() / caught.sum()) if caught.any() else None


def gate(dismissed: pd.DataFrame, env: LocalNormal) -> pd.DataFrame:
    """Keep only dismissals that resemble the site's earlier normal traffic."""
    return dismissed.loc[env.usual(dismissed[env.features])] if len(dismissed) else dismissed


def score_lab(det, lab: pd.DataFrame, feats: list[str]) -> dict:
    """Recall on lab attacks, overall and per attack type, and false alerts on the lab's benign flows."""
    hit = flagged(det, lab[feats])
    attack = (lab[LABEL_COL] != BENIGN).to_numpy()
    n, k = int(attack.sum()), int(hit[attack].sum())
    vetoable = anomaly_only_share(det, lab.loc[attack, feats]) if n else None
    per_class = pd.Series(hit[attack], index=lab.index[attack]).groupby(lab.loc[attack, LABEL_COL]).mean()
    nb = int((~attack).sum())
    return {"attacks": n, "caught": k, "recall": k / n if n else None, "recall_ci": list(wilson_interval(k, n)),
            "per_class": per_class.round(4).to_dict(), "vetoable_share": vetoable, "benign": nb,
            "benign_fpr": float(hit[~attack].mean()) if nb else None}


def morph(attacks: pd.DataFrame, normal: pd.DataFrame, feats: list[str], env: LocalNormal, a: float) -> pd.DataFrame:
    """Move each attack flow a fraction a of the way toward its nearest local normal flow (envelope metric)."""
    Z = (np.asarray(signed_log(attacks[env.features]), dtype=float) - env.center) / env.scale
    nearest = env.nn.kneighbors(Z, n_neighbors=1)[1][:, 0]
    target = normal[feats].to_numpy(dtype=float)[nearest]
    out = attacks.copy()
    out[feats] = (1 - a) * attacks[feats].to_numpy(dtype=float) + a * target
    return out


def contaminate(pool: pd.DataFrame, attacks: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """The fit pool with n attack flows mixed in, unlabelled, as an unnoticed attack in the 'normal' day would be."""
    if n == 0:
        return pool
    return pd.concat([pool, attacks.sample(n=min(n, len(attacks)), random_state=seed)], ignore_index=True)


def mislabel(triaged: pd.DataFrame, attacks: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """The triage set with n of its flows replaced by attacks an analyst wrongly dismissed as benign.
    `dismissed_attack` marks the replaced flows (bookkeeping only; never a model feature)."""
    keep = triaged.sample(n=max(0, len(triaged) - n), random_state=seed).assign(dismissed_attack=False)
    if n == 0:
        return keep
    wrong = attacks.sample(n=min(n, len(attacks)), random_state=seed).copy()
    wrong[LABEL_COL] = BENIGN
    wrong["dismissed_attack"] = True
    return pd.concat([keep, wrong[keep.columns.intersection(wrong.columns)]], ignore_index=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--lab-runs", nargs=3, type=Path, required=True, help="replicates A (poison source), B, C")
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--results", default="docs/results/attack_retention.md")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    lab = pd.concat([load_lab_run(p, feats) for p in args.lab_runs], ignore_index=True)
    rep_a, held = args.lab_runs[0].name, lab[lab["replicate"] != args.lab_runs[0].name]
    poison = lab[(lab["replicate"] == rep_a) & (lab[LABEL_COL] != BENIGN)]
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    blocks = [b for b in (load_session(p, feats) for p in study_sessions(args.study)) if len(b)]
    src_benign = src["train"][src["train"][LABEL_COL] == BENIGN].sample(
        min(20000, int((src["train"][LABEL_COL] == BENIGN).sum())), random_state=SEED)
    bench_attacks = tgt["test"][tgt["test"][LABEL_COL] != BENIGN]
    site_normal = LocalNormal(feats, fit_pool)
    n = args.service_flows
    rows: list[dict] = []

    def record(test: str, variant: str, det, seed: int, lab_set: pd.DataFrame, bench: bool = True, **meta) -> None:
        row = {"test": test, "variant": variant, "seed": seed, **meta,
               "lab": score_lab(det, lab_set, feats),
               "real_network_rate": score_blocks(det, blocks, feats)["rate"]}
        if bench:
            row["benchmark"] = score_attacks(det, tgt["test"], feats)
            row["benchmark"]["vetoable_share"] = anomaly_only_share(det, bench_attacks[feats])
        rows.append(row)
        print(f"[{test}] {variant} {meta} seed {seed}: lab recall {row['lab']['recall']:.3f} | "
              f"real-net {row['real_network_rate']:.3f}"
              + (f" | bench {row['benchmark']['macro_detection']:.3f}" if bench else ""), flush=True)

    for seed in seeds:
        labels = few_shot(tgt, args.k, 1000, seed)
        base = fit_detector(pd.concat([src["train"], labels]), src["val"], feats, args.model)
        triaged, _ = triage_sample(base, fit_pool, feats, n, seed)
        rep = fit_detector(pd.concat([src["train"], labels, triaged]), src["val"], feats, args.model)
        thr = copy.deepcopy(rep)
        thr.tune_anomaly_threshold(fit_pool[feats])
        variants = {"few-shot": base, "triaged, benchmark anomaly layer": rep,
                    "triaged + exemplar envelope": ExemplarEnvelope(rep, fit_pool[feats]),
                    "triaged + local anomaly threshold": thr,
                    "triaged + local refit anomaly": LocalRefit(rep, src_benign, fit_pool[feats]),
                    "triaged + two-envelope anomaly": TwoEnvelope(rep, fit_pool[feats])}
        for name, det in variants.items():                                         # R1
            record("R1 retention", name, det, seed, lab)

        for k in [0, 10, 30, 100, len(poison)]:                                     # R2, unlabelled pool
            pool = contaminate(fit_pool, poison, k, seed)
            record("R2 poisoned pool", "triaged + exemplar envelope", ExemplarEnvelope(rep, pool[feats]), seed,
                   held, bench=False, attacks_in_pool=k, share_of_pool=k / len(pool))
            t = copy.deepcopy(rep)
            t.tune_anomaly_threshold(pool[feats])
            record("R2 poisoned pool", "triaged + local anomaly threshold", t, seed, held, bench=False,
                   attacks_in_pool=k, share_of_pool=k / len(pool))
        for k in DISMISSED:                                                          # R2 analyst error, R5 gate
            wrong = mislabel(triaged, poison, k, seed)
            bad = fit_detector(pd.concat([src["train"], labels, wrong]), src["val"], feats, args.model)
            record("R2 dismissed attacks", "triaged + exemplar envelope", ExemplarEnvelope(bad, fit_pool[feats]),
                   seed, held, bench=False, dismissed=k)
            kept = gate(wrong, site_normal)
            gated = fit_detector(pd.concat([src["train"], labels, kept]), src["val"], feats, args.model)
            record("R5 gated triage", "triaged + exemplar envelope", ExemplarEnvelope(gated, fit_pool[feats]),
                   seed, held, bench=False, dismissed=k, kept=int(len(kept)),
                   attacks_kept=int(kept["dismissed_attack"].sum()))

        rng = np.random.default_rng(seed)                                            # R3
        for size in POOL_SIZES:
            sub = fit_pool.iloc[rng.choice(len(fit_pool), size=min(size, len(fit_pool)), replace=False)]
            record("R3 pool size", "triaged + exemplar envelope", ExemplarEnvelope(rep, sub[feats]), seed, lab,
                   pool_flows=len(sub))
            t = copy.deepcopy(rep)
            t.tune_anomaly_threshold(sub[feats])
            record("R3 pool size", "triaged + local anomaly threshold", t, seed, lab, pool_flows=len(sub))

        env = variants["triaged + exemplar envelope"]                                # R4
        attacks = lab[lab[LABEL_COL] != BENIGN]
        for a in ALPHAS:
            moved = morph(attacks, fit_pool, feats, env.local, a)
            for name in ("few-shot", "triaged, benchmark anomaly layer", "triaged + exemplar envelope",
                         "triaged + local anomaly threshold"):
                det = variants[name]
                hit = flagged(det, moved[feats])
                clf = np.asarray(det.predict(moved[feats]) != BENIGN)
                rows.append({"test": "R4 evasion", "variant": name, "seed": seed, "alpha": a,
                             "flagged": float(hit.mean()), "classifier_only": float(clf.mean()),
                             "near_normal": float(env.local.usual(moved[feats]).mean())})

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "features": len(feats),
           "portable": args.portable, "k": args.k, "service_flows": n, "seeds": seeds,
           "lab_runs": [p.name for p in args.lab_runs], "lab_attacks": int((lab[LABEL_COL] != BENIGN).sum()),
           "held_attacks": int((held[LABEL_COL] != BENIGN).sum()), "poison_attacks": int(len(poison)),
           "fit_pool_flows": int(len(fit_pool)), "eval_flows": int(sum(len(b) for b in blocks)),
           "runs": rows, "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(f"results in {out}")


def _mean(rows: list[dict], key) -> float:
    return float(np.mean([key(r) for r in rows]))


def to_markdown(res: dict) -> str:
    runs = res["runs"]
    pick = lambda test, **kv: [r for r in runs if r["test"] == test and all(r.get(k) == v for k, v in kv.items())]  # noqa: E731
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    L = ["# Attack retention, poisoning, data budget and evasion of the local repair", "",
         f"Generated on {res['generated']}. Model {res['model'].upper()}, {res['features']} features ({feats}), "
         f"k = {res['k']}, {res['service_flows']} triaged local flows, seeds {', '.join(map(str, res['seeds']))}. "
         f"Local model of normal fitted on {res['fit_pool_flows']:,} flows from an earlier evening; false alerts "
         f"measured on {res['eval_flows']:,} flows of a later evening. Lab attacks: {res['lab_attacks']} flows "
         f"from three isolated-lab replicates ({', '.join(res['lab_runs'])}); poisoning uses replicate A's "
         f"{res['poison_attacks']} attacks and is scored on the other two ({res['held_attacks']} attacks). "
         "Means over seeds; decision rules are in the script docstring.", "",
         "## R1. Does the repair keep catching attacks?", "",
         "| Variant | Lab attack recall | Benchmark detection | Caught by anomaly layer alone: lab / benchmark | "
         "Lab benign false alerts | Real-network alerts |",
         "|---|---|---|---|---|---|"]
    variants = list(dict.fromkeys(r["variant"] for r in pick("R1 retention")))
    share = lambda x: f"{x:.1%}" if x == x else "—"  # noqa: E731
    for v in variants:
        rs = pick("R1 retention", variant=v)
        L.append(f"| {v} | {_mean(rs, lambda r: r['lab']['recall']):.1%} | "
                 f"{_mean(rs, lambda r: r['benchmark']['macro_detection']):.3f} | "
                 f"{share(_mean(rs, lambda r: r['lab']['vetoable_share'] if r['lab']['vetoable_share'] is not None else np.nan))} / "
                 f"{share(_mean(rs, lambda r: r['benchmark']['vetoable_share'] if r['benchmark']['vetoable_share'] is not None else np.nan))} | "
                 f"{_mean(rs, lambda r: r['lab']['benign_fpr']):.1%} | {_mean(rs, lambda r: r['real_network_rate']):.1%} |")
    classes = sorted({c for r in pick("R1 retention") for c in r["lab"]["per_class"]})
    L += ["", "Lab recall by attack type:", "", "| Variant | " + " | ".join(classes) + " |",
          "|---|" + "---|" * len(classes)]
    for v in variants:
        rs = pick("R1 retention", variant=v)
        L.append(f"| {v} | " + " | ".join(f"{_mean(rs, lambda r: r['lab']['per_class'].get(c, np.nan)):.0%}"
                                          for c in classes) + " |")
    base = _mean(pick("R1 retention", variant="few-shot"), lambda r: r["lab"]["recall"])
    rep = _mean(pick("R1 retention", variant="triaged + exemplar envelope"), lambda r: r["lab"]["recall"])
    L += ["", f"**Rule R1:** lab recall {base:.1%} → {rep:.1%} ({(rep - base) * 100:+.1f} points); "
          f"{'retained' if rep - base >= -0.02 else 'NOT retained'} (threshold −2 points).", "",
          "## R2. Poisoning the local model of normal", "",
          "| Fit pool contamination | Variant | Held-out lab recall | Real-network alerts |", "|---|---|---|---|"]
    for v in ("triaged + exemplar envelope", "triaged + local anomaly threshold"):
        for k in sorted({r["attacks_in_pool"] for r in pick("R2 poisoned pool")}):
            rs = pick("R2 poisoned pool", variant=v, attacks_in_pool=k)
            L.append(f"| {k} attacks ({rs[0]['share_of_pool']:.1%}) | {v} | "
                     f"{_mean(rs, lambda r: r['lab']['recall']):.1%} | {_mean(rs, lambda r: r['real_network_rate']):.1%} |")
    clean = pick("R2 poisoned pool", variant="triaged + exemplar envelope", attacks_in_pool=0)
    held_classes = sorted({c for r in pick("R2 dismissed attacks") for c in r["lab"]["per_class"]})
    pc = lambda rs: " | ".join(f"{_mean(rs, lambda r: r['lab']['per_class'].get(c, np.nan)):.0%}" for c in held_classes)  # noqa: E731
    L += ["", "Attacks wrongly dismissed as benign during triage (R2), and the same with dismissals gated by the "
          "local envelope (R5, exploratory):", "",
          "| Dismissed attacks | Triage | Dismissals kept (attacks) | Held-out lab recall | " + " | ".join(held_classes)
          + " | Real-network alerts |", "|---|---|---|---|" + "---|" * len(held_classes) + "---|",
          f"| 0 | — | 30 (0) | {_mean(clean, lambda r: r['lab']['recall']):.1%} | {pc(clean)} | "
          f"{_mean(clean, lambda r: r['real_network_rate']):.1%} |"]
    for k in DISMISSED:
        for test, label in (("R2 dismissed attacks", "ungated"), ("R5 gated triage", "gated")):
            rs = pick(test, dismissed=k)
            kept = (f"{_mean(rs, lambda r: r['kept']):.0f} ({_mean(rs, lambda r: r['attacks_kept']):.1f})"
                    if test.startswith("R5") else f"30 ({k})")
            L.append(f"| {k} | {label} | {kept} | {_mean(rs, lambda r: r['lab']['recall']):.1%} | {pc(rs)} | "
                     f"{_mean(rs, lambda r: r['real_network_rate']):.1%} |")
    L += ["", "## R3. How much local normal traffic is needed?", "",
          "| Fit pool flows | Variant | Real-network alerts | Lab recall | Benchmark detection |", "|---|---|---|---|---|"]
    full = {v: _mean(pick("R1 retention", variant=v), lambda r: r["real_network_rate"])
            for v in ("triaged + exemplar envelope", "triaged + local anomaly threshold")}
    for v in full:
        for size in sorted({r["pool_flows"] for r in pick("R3 pool size")}):
            rs = pick("R3 pool size", variant=v, pool_flows=size)
            L.append(f"| {size:,} | {v} | {_mean(rs, lambda r: r['real_network_rate']):.1%} | "
                     f"{_mean(rs, lambda r: r['lab']['recall']):.1%} | {_mean(rs, lambda r: r['benchmark']['macro_detection']):.3f} |")
        L.append(f"| {res['fit_pool_flows']:,} (all) | {v} | {full[v]:.1%} | — | — |")
    L += ["", "## R4. Evasion: attacks moved toward the nearest local normal flow", "",
          "| a | " + " | ".join(variants[i] for i in (0, 1, 2, 3)) + " | Inside the local envelope |",
          "|---|---|---|---|---|---|"]
    gaps = []
    for a in ALPHAS:
        vals = [_mean(pick("R4 evasion", variant=variants[i], alpha=a), lambda r: r["flagged"]) for i in (0, 1, 2, 3)]
        near = _mean(pick("R4 evasion", variant=variants[2], alpha=a), lambda r: r["near_normal"])
        gaps.append(vals[1] - vals[2])
        L.append(f"| {a:.1f} | " + " | ".join(f"{v:.1%}" for v in vals) + f" | {near:.1%} |")
    worst = max(gaps)
    L += ["", f"**Rule R4:** largest gap between the benchmark anomaly layer and the exemplar envelope is "
          f"{worst * 100:.1f} points; the envelope {'opens' if worst > 0.05 else 'does not open'} a new evasion "
          "path (threshold 5 points).", "", "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
