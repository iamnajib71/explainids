"""Does adding local benign *service* traffic to the adaptation set remove the service regression?

Usage:
  python scripts/service_aware_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --fit-profile data/lab/run_20261025T051701Z/flows_labelled.csv \
      --held-profile data/lab/run_20261025T051751Z/flows_labelled.csv \
      --shots 10,50 --service-flows 0,30,100 --seeds 42,1 --results docs/results/service_aware.md

Background: matched-control evaluation showed limited-label adaptation raising target attack detection
while pushing false alerts on legitimate SSH/FTP/HTTP traffic to 26-70%. Its benign sample is drawn
from the target dataset's training period, which contains no flows resembling those services, so the
model is never shown that they are normal. This tests the direct remedy.

Design. Every condition trains on the source dataset plus k oracle-balanced labelled attack flows per
class from the target's training period plus 1,000 target benign flows -- the condition that regressed.
Service-aware conditions add `--service-flows` benign flows drawn from the *fit* profile only, stratified
by destination port so each service is represented. Evaluation uses:

  target test    the target dataset's full held-out test split (attack detection)
  held-in        the remainder of the fit profile, never trained on (same configuration)
  held-out       the entire second profile (a different service configuration, never trained on)

The fit/held-in split is by flow and disjoint; no evaluated flow is ever trained on. A reference
condition trains on both datasets with no service flows. Reported: class-balanced attack detection,
benign false-alert rate with 95% Wilson intervals, and the predicted classes assigned to benign flows.
Accuracy is never reported alone (project rule 4).
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from ids import SEED
from ids.data import BENIGN, LABEL_COL, dedup_global, feature_columns, stratified_sample, temporal_split
from ids.evaluate import binary_report, report, wilson_interval
from ids.models import Detector
from ids.scoring import align_columns


def load_dataset(path: str, cap: int) -> dict:
    df = dedup_global(pd.read_parquet(path))
    train, val, test = temporal_split(df)
    return {"name": Path(path).stem, "train": stratified_sample(train, cap), "val": val, "test": test}


def load_profile(path: str, feats: list[str]) -> pd.DataFrame:
    """An all-benign service capture, aligned to the model feature schema."""
    raw = pd.read_csv(path, low_memory=False)
    raw.columns = [c.strip() for c in raw.columns]
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise ValueError(f"{Path(path).name}: {len(missing)} features missing, e.g. {missing[:5]}")
    labels = aligned[LABEL_COL].unique() if LABEL_COL in aligned else []
    if list(labels) != [BENIGN]:
        raise ValueError(f"{Path(path).name}: expected an all-benign capture, found {list(labels)}")
    numeric = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    out = aligned.loc[valid].copy()
    out[feats] = numeric.loc[valid]
    return out.reset_index(drop=True)


def service_key(df: pd.DataFrame) -> pd.Series:
    """Group flows by destination port so a sample covers every service, not just the common one."""
    port = next((c for c in df.columns if c.strip().lower() in {"dst port", "destination port"}), None)
    return df[port].astype(int).astype(str) if port else pd.Series("all", index=df.index)


def split_profile(profile: pd.DataFrame, n_fit: int, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Take n_fit flows stratified by service; the remainder is held in for evaluation."""
    if n_fit == 0:
        return profile.iloc[:0], profile
    groups, rng = service_key(profile), np.random.default_rng(seed)
    share = n_fit / len(profile)
    picked: list[int] = []
    for _, idx in profile.groupby(groups).groups.items():
        idx = np.asarray(list(idx))
        take = min(len(idx) - 1, max(1, int(round(len(idx) * share))))
        if take > 0:
            picked.extend(rng.choice(idx, size=take, replace=False).tolist())
    fit = profile.loc[picked]
    held = profile.drop(index=picked)
    assert not set(fit.index) & set(held.index), "fit and held-in flows must be disjoint"
    return fit, held


def few_shot(target: dict, k: int, benign: int, seed: int) -> pd.DataFrame:
    tr = target["train"]
    parts = [g.sample(min(k, len(g)), random_state=seed) for label, g in tr.groupby(LABEL_COL) if label != BENIGN]
    parts.append(tr[tr[LABEL_COL] == BENIGN].sample(min(benign, int((tr[LABEL_COL] == BENIGN).sum())), random_state=seed))
    return pd.concat(parts)


def fit_detector(train: pd.DataFrame, val: pd.DataFrame, feats: list[str], model: str) -> Detector:
    det = Detector(model).fit(train[feats], train[LABEL_COL])
    benign = train[train[LABEL_COL] == BENIGN]
    det.fit_anomaly(benign[feats])
    det.tune_anomaly_threshold(val[val[LABEL_COL] == BENIGN][feats])
    return det


def score_attacks(det: Detector, test: pd.DataFrame, feats: list[str]) -> dict:
    X, y = test[feats], test[LABEL_COL]
    pred = det.predict(X)
    flagged = (pred != BENIGN) | det.anomaly(X)[1]
    rep = binary_report(y, flagged)
    per_class = pd.Series(flagged, index=y.index).groupby(y).mean().drop(BENIGN, errors="ignore")
    return {"flows": int(len(y)), "recall": rep["recall"], "recall_ci": rep["recall_ci"],
            "fpr": rep["fpr"], "macro_detection": float(per_class.mean()),
            "per_class": per_class.round(4).to_dict()}


def score_benign(det: Detector, profile: pd.DataFrame, feats: list[str]) -> dict:
    """False alerts on an all-benign capture, with the attack classes they were assigned."""
    if profile.empty:
        return {"flows": 0, "fpr": None, "fpr_ci": [None, None], "called": {}}
    X = profile[feats]
    pred = det.predict(X)
    flagged = (pred != BENIGN) | det.anomaly(X)[1]
    fp, n = int(flagged.sum()), int(len(profile))
    called = pd.Series(pred[pred != BENIGN]).value_counts().to_dict()
    by_service = (pd.Series(flagged, index=profile.index).groupby(service_key(profile)).mean().round(4).to_dict())
    return {"flows": n, "false_alerts": fp, "fpr": fp / n, "fpr_ci": list(wilson_interval(fp, n)),
            "called": {str(k): int(v) for k, v in called.items()}, "by_service_port": by_service}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--fit-profile", required=True, help="all-benign capture that may contribute training flows")
    ap.add_argument("--held-profile", required=True, help="all-benign capture in a different configuration, never trained on")
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--shots", default="10,50")
    ap.add_argument("--service-flows", default="0,30,100")
    ap.add_argument("--seeds", default="42,1")
    ap.add_argument("--local-benign", type=int, default=1000)
    ap.add_argument("--results", default="docs/results/service_aware.md")
    args = ap.parse_args()
    shots = [int(s) for s in args.shots.split(",")]
    services = [int(s) for s in args.service_flows.split(",")]
    seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    fit_profile = load_profile(args.fit_profile, feats)
    held_profile = load_profile(args.held_profile, feats)
    rows = []

    def run(config: str, train: pd.DataFrame, val: pd.DataFrame, held_in: pd.DataFrame, **meta):
        det = fit_detector(train, val, feats, args.model)
        row = {"config": config, **meta, "training_rows": int(len(train)),
               "target_test": score_attacks(det, tgt["test"], feats),
               "held_in_profile": score_benign(det, held_in, feats),
               "held_out_profile": score_benign(det, held_profile, feats)}
        rows.append(row)
        hi, ho = row["held_in_profile"], row["held_out_profile"]
        print(f"{config} {meta}: target det {row['target_test']['macro_detection']:.3f} | "
              f"held-in FPR {hi['fpr'] if hi['fpr'] is None else format(hi['fpr'], '.3f')} | "
              f"held-out FPR {ho['fpr']:.3f}", flush=True)

    run(f"source only: {src['name']}", src["train"], src["val"], fit_profile)
    run("both environments", pd.concat([src["train"], tgt["train"]]),
        pd.concat([src["val"], tgt["val"]]), fit_profile)
    for k in shots:
        for n_service in services:
            for seed in seeds:
                local = few_shot(tgt, k, args.local_benign, seed)
                service_fit, held_in = split_profile(fit_profile, n_service, seed)
                train = pd.concat([src["train"], local, service_fit]) if n_service else pd.concat([src["train"], local])
                run("few-shot" + (f" + {n_service} service flows" if n_service else " (no service flows)"),
                    train, src["val"], held_in, k=k, service_flows=n_service, service_added=int(len(service_fit)),
                    seed=seed)

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "data_seed": SEED,
           "source": src["name"], "target": tgt["name"], "local_benign": args.local_benign,
           "fit_profile": args.fit_profile, "held_profile": args.held_profile,
           "fit_profile_flows": int(len(fit_profile)), "held_profile_flows": int(len(held_profile)),
           "shots": shots, "service_flows": services, "seeds": seeds, "runs": rows,
           "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"results in {out}")


def to_markdown(res: dict) -> str:
    md = ["# Service-aware adaptation", "",
          f"Generated on {res['generated']}. Model {res['model'].upper()}; source {res['source']}, "
          f"target {res['target']}. Each adaptation condition adds k oracle-balanced labelled attack flows per "
          f"class plus {res['local_benign']:,} target benign flows, and optionally benign flows from the fit "
          f"profile ({res['fit_profile_flows']} flows). Held-in flows are the untrained remainder of that profile; "
          f"the held-out profile ({res['held_profile_flows']} flows, different service configuration) is never "
          "trained on. Detection is class-balanced; service columns are benign false-alert rates with 95% Wilson "
          "intervals.", "",
          "| Training | k | Service flows requested (actually added) | Target detection | Held-in FPR | Held-out FPR |",
          "|---|---|---|---|---|---|"]
    frame = pd.DataFrame(res["runs"])
    for (config, k, n), group in frame.groupby(
            ["config", frame.get("k", pd.Series(dtype=float)), frame.get("service_flows", pd.Series(dtype=float))],
            dropna=False, sort=False):
        det = np.mean([r["macro_detection"] for r in group["target_test"]])
        def rate(col):
            vals = [r["fpr"] for r in group[col] if r["fpr"] is not None]
            if not vals:
                return "n/a"
            lo = min(min(r["fpr_ci"]) for r in group[col] if r["fpr"] is not None)
            hi = max(max(r["fpr_ci"]) for r in group[col] if r["fpr"] is not None)
            return f"{np.mean(vals):.1%} ({lo:.1%}-{hi:.1%})"
        added = sorted({int(a) for a in group.get("service_added", pd.Series(dtype=float)).dropna()})
        n_text = "" if pd.isna(n) else f"{int(n)}" + (f" ({'/'.join(map(str, added))})" if added else "")
        md.append(f"| {config} | {'' if pd.isna(k) else int(k)} | {n_text} | "
                  f"{det:.3f} | {rate('held_in_profile')} | {rate('held_out_profile')} |")
    md += ["", "Benign flows carry no attack denominator, so detection is not defined for the profile columns. "
           "Service flows used for training are excluded from the held-in evaluation. The sampler takes at "
           "least one flow from every destination port with two or more flows, so the number actually added can exceed "
           "the number requested. Accuracy is not reported (rule 4).", "", f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    main()
