"""Can repetition recover what the local veto hides? (docs/PREREGISTRATION_ESCALATION.md)

Usage:
  python scripts/escalation_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --fit-sessions $(cat data/study_sessions.txt) \
      --studies data/sensor/study_wifi_20261101.json data/sensor/study_wifi_20261108.json \
      [--portable] --results docs/results/escalation.md

The leave-one-class-out design of `unseen_veto_eval.py`, unchanged, with one addition: anomaly alerts the exemplar
envelope vetoes ("demoted") return to the queue when at least N share a destination address and port inside 60
seconds. N is set from the earlier evening alone (1 + the most repetition it shows, floor 3), per fitted model.

H1: pooled over classes, test splits and seeds, at most 10% of anomaly-only unseen detections stay lost.
H2: on each later evening the alert rate rises by no more than 0.2 percentage points.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from real_network_eval import study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset  # noqa: E402
from unseen_veto_eval import MIN_FLOWS, without  # noqa: E402

from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope  # noqa: E402
from ids.escalation import escalated, repeat_counts, threshold_from  # noqa: E402
from ids.repair import triage_sample  # noqa: E402
from ids.scoring import align_columns  # noqa: E402

RECOVERY_RULE, PRICE_RULE = 0.10, 0.002


def load_block(folder: Path, feats: list[str]) -> pd.DataFrame:
    """A validated sensor session in the model schema, with start time (s) and destination key as metadata."""
    raw = pd.read_csv(folder / "validated.csv", low_memory=False)
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise ValueError(f"{folder.name}: {len(missing)} features missing")
    numeric = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    out = numeric.loc[valid].reset_index(drop=True)
    start = pd.to_datetime(raw.loc[valid, "Timestamp"], errors="coerce", dayfirst=True).reset_index(drop=True)
    out["_t"] = (start - start.min()).dt.total_seconds().fillna(0.0)
    out["_key"] = (raw.loc[valid, "Dst IP"].astype(str) + ":" + raw.loc[valid, "Dst Port"].astype(str)).to_numpy()
    out[LABEL_COL] = BENIGN
    out.attrs["span_seconds"] = float(out["_t"].max()) if len(out) else 0.0
    return out


def benchmark_meta(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    ts = pd.to_datetime(frame["Timestamp"], errors="coerce", format="mixed")
    t = (ts - ts.min()).dt.total_seconds().fillna(0.0).to_numpy()
    return t, (frame["Dst IP"].astype(str) + ":" + frame["Dst Port"].astype(str)).to_numpy()


def flags(rep, env, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Classifier alert, benchmark anomaly alert, and demoted (anomaly-only alerts the envelope vetoes)."""
    clf = np.asarray(rep.predict(X) != BENIGN)
    anom = np.asarray(rep.anomaly(X)[1])
    kept = np.asarray(env.anomaly(X)[1])
    return clf, anom, anom & ~clf & ~kept


def site_threshold(rep, env, fit_blocks: list[pd.DataFrame], feats: list[str]) -> int:
    counts = [repeat_counts(b["_t"].to_numpy(), b["_key"].to_numpy(), flags(rep, env, b[feats])[2]) for b in fit_blocks]
    return threshold_from(np.concatenate(counts) if counts else np.array([], dtype=int))


def score_evening(rep, env, blocks: list[pd.DataFrame], feats: list[str], n: int) -> dict:
    flows = alerts = up = 0
    seconds = 0.0
    for b in blocks:
        clf, anom, dem = flags(rep, env, b[feats])
        esc = escalated(b["_t"].to_numpy(), b["_key"].to_numpy(), dem, n)
        flows += len(b)
        alerts += int((clf | (anom & ~dem)).sum())
        up += int(esc.sum())
        seconds += b.attrs["span_seconds"]
    return {"flows": flows, "alerts": alerts, "escalated": up, "hours": seconds / 3600}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--studies", nargs="+", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--classes", default="", help="comma-separated subset, for smoke tests only")
    ap.add_argument("--results", default="docs/results/escalation.md")
    args = ap.parse_args()

    t0 = time.perf_counter()
    seeds = [int(s) for s in args.seeds.split(",")]
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    fit_blocks = [b for b in (load_block(Path(s), feats) for s in args.fit_sessions) if len(b)]
    fit_pool = pd.concat([b[feats + [LABEL_COL]] for b in fit_blocks], ignore_index=True)
    if "Dst Port" not in fit_pool:  # triage sampling spreads over services even when the port is not a feature
        fit_pool["Dst Port"] = np.concatenate([b["_key"].str.rsplit(":", n=1).str[1].astype(float).astype(int)
                                               for b in fit_blocks])
    evenings = {p.stem: [b for b in (load_block(f, feats) for f in study_sessions(p)) if len(b)] for p in args.studies}
    tests = {src["name"]: src["test"], tgt["name"]: tgt["test"]}
    classes = sorted({c for t in tests.values() for c, n in t[LABEL_COL].value_counts().items()
                      if c != BENIGN and n >= MIN_FLOWS})
    if args.classes:
        classes = [c for c in classes if c in set(args.classes.split(","))]
    rows = []
    for seed in seeds:
        for cls in classes:
            s, t = without(src, cls), without(tgt, cls)
            labels = few_shot(t, args.k, 1000, seed)
            base = fit_detector(pd.concat([s["train"], labels]), s["val"], feats, args.model)
            triaged, _ = triage_sample(base, fit_pool, feats, args.service_flows, seed)
            rep = fit_detector(pd.concat([s["train"], labels, triaged]), s["val"], feats, args.model)
            env = ExemplarEnvelope(rep, fit_pool[feats])
            n = site_threshold(rep, env, fit_blocks, feats)
            row = {"seed": seed, "class": cls, "n": n, "splits": {},
                   "evenings": {name: score_evening(rep, env, blocks, feats, n) for name, blocks in evenings.items()}}
            for name, test in tests.items():
                part = test[test[LABEL_COL] == cls]
                if len(part) < MIN_FLOWS:
                    continue
                clf, anom, dem = flags(rep, env, part[feats])
                tt, key = benchmark_meta(part)
                esc = escalated(tt, key, dem, n)
                row["splits"][name] = {"flows": int(len(part)), "classifier": int(clf.sum()),
                                       "anomaly_only": int((anom & ~clf).sum()), "vetoed": int(dem.sum()),
                                       "escalated": int(esc.sum())}
            rows.append(row)
            print(seed, cls, n, json.dumps({k: (v["anomaly_only"], v["vetoed"], v["escalated"])
                                            for k, v in row["splits"].items()}), flush=True)

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "features": len(feats),
           "portable": args.portable, "k": args.k, "service_flows": args.service_flows, "seeds": seeds,
           "fit_pool_flows": int(len(fit_pool)), "window_seconds": 60, "rows": rows,
           "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(f"results in {out}")


def summarise(res: dict) -> dict:
    only = vetoed = esc = 0
    per_class: dict[str, list[int]] = {}
    per_seed: dict[int, list[int]] = {}
    for r in res["rows"]:
        for d in r["splits"].values():
            only += d["anomaly_only"]; vetoed += d["vetoed"]; esc += d["escalated"]
            for bucket, key in ((per_class, r["class"]), (per_seed, r["seed"])):
                b = bucket.setdefault(key, [0, 0, 0])
                b[0] += d["anomaly_only"]; b[1] += d["vetoed"]; b[2] += d["escalated"]
    evenings = {}
    for name in res["rows"][0]["evenings"]:
        e = [r["evenings"][name] for r in res["rows"]]
        base = np.mean([x["alerts"] / x["flows"] for x in e])
        plus = np.mean([(x["alerts"] + x["escalated"]) / x["flows"] for x in e])
        evenings[name] = {"rate": float(base), "rate_escalated": float(plus), "rise": float(plus - base),
                          "escalated_per_hour": float(np.mean([x["escalated"] / x["hours"] for x in e if x["hours"]]))}
    return {"anomaly_only": only, "vetoed": vetoed, "escalated": esc,
            "lost_before": vetoed / only if only else 0.0, "lost_after": (vetoed - esc) / only if only else 0.0,
            "per_class": per_class, "per_seed": per_seed, "evenings": evenings,
            "n_range": [min(r["n"] for r in res["rows"]), max(r["n"] for r in res["rows"])]}


def to_markdown(res: dict) -> str:
    s = summarise(res)
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    h1 = s["lost_after"] <= RECOVERY_RULE
    h2 = all(e["rise"] <= PRICE_RULE for e in s["evenings"].values())
    L = ["# Repetition escalation: recovering what the local veto hides", "",
         f"Generated on {res['generated']}. {res['model'].upper()}, {res['features']} features ({feats}), k = {res['k']}, "
         f"{res['service_flows']} triaged local flows, seeds {', '.join(map(str, res['seeds']))}. Each attack class is "
         f"left out of all training in turn. A vetoed anomaly alert returns to the queue when at least N vetoed alerts "
         f"share its destination address and port within {res['window_seconds']} s; N is 1 + the most repetition on the "
         f"earlier evening ({res['fit_pool_flows']:,} flows), floor 3: N ranged {s['n_range'][0]}–{s['n_range'][1]} "
         "over the fitted models. Rule in docs/PREREGISTRATION_ESCALATION.md.", "",
         "| Unseen class | Anomaly-only detections | Vetoed by the envelope | Returned by escalation | Still lost |",
         "|---|---|---|---|---|"]
    for cls, (only, vetoed, esc) in sorted(s["per_class"].items()):
        if vetoed:
            L.append(f"| {cls} | {only:,} | {vetoed:,} | {esc:,} | {vetoed - esc:,} |")
    L += [f"| **All classes** | **{s['anomaly_only']:,}** | **{s['vetoed']:,}** | **{s['escalated']:,}** | "
          f"**{s['vetoed'] - s['escalated']:,}** |", "",
          "Per seed, share still lost: " + "; ".join(
              f"seed {k} {(v[1] - v[2]) / v[0]:.1%}" for k, v in sorted(s["per_seed"].items()) if v[0]) + ".", "",
          f"**H1 (recovery):** lost {s['lost_before']:.1%} before escalation, {s['lost_after']:.1%} after "
          f"(rule: at most {RECOVERY_RULE:.0%}): **{'confirmed' if h1 else 'not confirmed'}**.", "",
          "| Evening | Alert rate, envelope | With escalation | Rise | Escalated alerts per hour |", "|---|---|---|---|---|"]
    for name, e in s["evenings"].items():
        L.append(f"| {name} | {e['rate']:.2%} | {e['rate_escalated']:.2%} | {e['rise'] * 100:+.2f} points | "
                 f"{e['escalated_per_hour']:.1f} |")
    L += ["", f"**H2 (price):** rise at most {PRICE_RULE * 100:.1f} points on each evening: "
              f"**{'confirmed' if h2 else 'not confirmed'}**.", "",
          "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
