"""Attack Night: how long does an attack go unnoticed behind the alert queue? (docs/PREREGISTRATION_ATTACK_NIGHT.md)

  python scripts/attack_night_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab-runs <replicate A> <B> <C> --fit-sessions $(cat data/study_sessions.txt) \
      --study data/sensor/study_wifi_20261101.json [--portable] --results docs/results/attack_night.md

The untouched second evening's blocks are joined into one hour of observed traffic; a whole lab attack campaign
(about a minute) is inserted at random moments with its own relative timing; an analyst works the alerts first
in, first out at one every s seconds. Time to notice is when the analyst reaches the first attack alert.
Aggregates only; accuracy is never reported (rule 4).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_retention_eval import flagged, gate, mislabel  # noqa: E402
from real_network_eval import study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset  # noqa: E402

from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope, LocalNormal  # noqa: E402
from ids.repair import triage_sample  # noqa: E402
from ids.scoring import align_columns  # noqa: E402

BLOCK_SECONDS = 300
SERVICE_SECONDS = [30, 60, 120, 300]
PRIMARY_S = 60
INJECTIONS = 20
DISMISSED = 3
CONDITIONS = ["Deployed", "Repaired", "Poisoned", "Poisoned, gated"]
DISMISSED_TYPES = ["PortScan", "SYN-Burst"]
BIN = 10


def load_timed(path: Path, feats: list[str]) -> pd.DataFrame:
    """Flows in the model schema with start time and end time (seconds), invalid rows dropped."""
    raw = pd.read_csv(path, low_memory=False)
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise ValueError(f"{path}: {len(missing)} features missing")
    numeric = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    out = numeric.loc[valid].reset_index(drop=True)
    start = pd.to_datetime(aligned.loc[valid, "Timestamp"], errors="coerce").reset_index(drop=True)
    dur = pd.to_numeric(aligned.loc[valid, "Flow Duration"], errors="coerce").fillna(0).reset_index(drop=True) / 1e6
    out["t"] = (start - start.min()).dt.total_seconds()
    out["t_end"] = out["t"] + dur
    out[LABEL_COL] = aligned.loc[valid, LABEL_COL].reset_index(drop=True) if LABEL_COL in aligned else BENIGN
    return out


def evening(study: Path, feats: list[str]) -> pd.DataFrame:
    """The evening's blocks joined end to end: block b occupies [300 b, 300 (b + 1)) seconds."""
    parts = []
    for b, folder in enumerate(study_sessions(study)):
        blk = load_timed(folder / "validated.csv", feats)
        blk[["t", "t_end"]] += BLOCK_SECONDS * b
        parts.append(blk)
    return pd.concat(parts, ignore_index=True)


def notice_time(alert_end: np.ndarray, is_attack: np.ndarray, s: float) -> float | None:
    """FIFO analyst, one alert every s seconds from time 0: when the first attack alert is reached."""
    order = np.argsort(alert_end, kind="stable")
    free = 0.0
    for i in order:
        start = max(free, alert_end[i])
        if is_attack[i]:
            return start
        free = start + s
    return None


def run_injection(bg_flag: np.ndarray, bg_end: np.ndarray, atk: pd.DataFrame, atk_flag: np.ndarray,
                  t0: float, s: float) -> dict:
    ends = np.concatenate([bg_end[bg_flag], atk["t_end"].to_numpy()[atk_flag] + t0])
    is_attack = np.concatenate([np.zeros(int(bg_flag.sum()), bool), np.ones(int(atk_flag.sum()), bool)])
    reached = notice_time(ends, is_attack, s) if atk_flag.any() else None
    campaign_end = t0 + float(atk["t_end"].max())
    queue_ahead = int((bg_end[bg_flag] < (atk["t_end"].to_numpy()[atk_flag].min() + t0)).sum()) if atk_flag.any() else None
    return {"t0": t0, "missed": reached is None, "time_to_notice": None if reached is None else reached - t0,
            "over_before_noticed": reached is None or reached > campaign_end, "alerts_before_attack": queue_ahead}


def timeline(bg_flag, bg_end, atk, atk_flag, t0, horizon=3600) -> dict:
    """Per-10-second counts of alerts (household vs attack) for the console's Attack Night view."""
    edges = np.arange(0, horizon + BIN, BIN)
    return {"household": np.histogram(bg_end[bg_flag], edges)[0].tolist(),
            "attack": np.histogram(atk["t_end"].to_numpy()[atk_flag] + t0, edges)[0].tolist()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--lab-runs", nargs=3, type=Path, required=True, help="replicates A (dismissed source), B, C")
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--results", default="docs/results/attack_night.md")
    ap.add_argument("--timeline", type=Path, help="write the median-case timeline here (web/data/attack_night.json)")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]

    t0_clock = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    from real_network_eval import load_session  # same loader as the study, for the fit pool
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    bg = evening(args.study, feats)
    hour = BLOCK_SECONDS * len(study_sessions(args.study))
    camp = {p.name: load_timed(p / "flows_labelled.csv", feats) for p in args.lab_runs}
    rep_a = args.lab_runs[0].name
    dismissable = camp[rep_a][camp[rep_a][LABEL_COL] != BENIGN]
    campaigns = {name: c[c[LABEL_COL] != BENIGN].reset_index(drop=True) for name, c in camp.items() if name != rep_a}
    site_normal = LocalNormal(feats, fit_pool)

    rows, timelines = [], {}
    for seed in seeds:
        labels = few_shot(tgt, args.k, 1000, seed)
        base = fit_detector(pd.concat([src["train"], labels]), src["val"], feats, args.model)
        triaged, _ = triage_sample(base, fit_pool, feats, args.service_flows, seed)
        poisoned_set = mislabel(triaged, dismissable, DISMISSED, seed)
        gated_set = pd.concat([poisoned_set[~poisoned_set["dismissed_attack"]],
                               gate(poisoned_set[poisoned_set["dismissed_attack"]], site_normal)])
        dets = {"Deployed": base}
        for name, rep_set in [("Repaired", triaged), ("Poisoned", poisoned_set), ("Poisoned, gated", gated_set)]:
            clean = rep_set.drop(columns=["dismissed_attack"], errors="ignore").assign(**{LABEL_COL: BENIGN})
            det = fit_detector(pd.concat([src["train"], labels, clean]), src["val"], feats, args.model)
            dets[name] = ExemplarEnvelope(det, fit_pool[feats])
        rng = np.random.default_rng(seed)
        starts = {name: rng.uniform(0, hour - float(c["t_end"].max()), INJECTIONS) for name, c in campaigns.items()}
        for cond, det in dets.items():
            bg_flag = flagged(det, bg[feats])
            for cname, c in campaigns.items():
                atk_flag = flagged(det, c[feats])
                types = c[LABEL_COL].to_numpy()
                per_type = {t: float(atk_flag[types == t].mean()) for t in np.unique(types)}
                for j, t0 in enumerate(starts[cname]):
                    for s in SERVICE_SECONDS:
                        r = run_injection(bg_flag, bg["t_end"].to_numpy(), c, atk_flag, float(t0), s)
                        rows.append({"condition": cond, "seed": seed, "replicate": cname, "injection": j, "s": s,
                                     "household_alerts_per_hour": float(bg_flag.sum() * 3600 / hour),
                                     "attack_flows_flagged": float(atk_flag.mean()), "per_type": per_type, **r})
                    if seed == seeds[0] and cname == next(iter(campaigns)):
                        timelines.setdefault(cond, []).append((float(t0), timeline(bg_flag, bg["t_end"].to_numpy(),
                                                                                    c, atk_flag, float(t0), hour)))
            print(f"seed {seed} {cond}: household alerts/h {rows[-1]['household_alerts_per_hour']:.0f}, "
                  f"attack flows flagged {rows[-1]['attack_flows_flagged']:.2f}", flush=True)

    df = pd.DataFrame(rows)
    res = {"generated": time.strftime("%Y-%m-%d"), "features": len(feats), "portable": args.portable,
           "seeds": seeds, "hour_seconds": hour, "evening_flows": int(len(bg)),
           "campaign_flows": {k: int(len(v)) for k, v in campaigns.items()}, "summary": summarise(df),
           "minutes": (time.perf_counter() - t0_clock) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    if args.timeline:
        args.timeline.write_text(json.dumps(median_case(timelines, df, seeds[0], next(iter(campaigns)), hour)),
                                 encoding="utf-8")
    print(f"results in {out}")


def summarise(df: pd.DataFrame) -> dict:
    out = {}
    for s, g in df.groupby("s"):
        by = {}
        for cond, h in g.groupby("condition", sort=False):
            ttn = h["time_to_notice"].astype(float)
            by[cond] = {"median_minutes": float(np.nanmedian(ttn) / 60) if ttn.notna().any() else None,
                        "q25_minutes": float(np.nanpercentile(ttn, 25) / 60) if ttn.notna().any() else None,
                        "q75_minutes": float(np.nanpercentile(ttn, 75) / 60) if ttn.notna().any() else None,
                        "missed": float(h["missed"].mean()), "over_before_noticed": float(h["over_before_noticed"].mean()),
                        "household_alerts_per_hour": float(h["household_alerts_per_hour"].mean()),
                        "attack_flows_flagged": float(h["attack_flows_flagged"].mean()),
                        "dismissed_types_flagged": float(np.mean([np.mean([p.get(t, np.nan) for t in DISMISSED_TYPES])
                                                                  for p in h["per_type"]])),
                        "per_seed_median_minutes": [float(np.nanmedian(x["time_to_notice"].astype(float)) / 60)
                                                    if x["time_to_notice"].notna().any() else None
                                                    for _, x in h.groupby("seed")]}
        d, r = (g[g["condition"] == c].sort_values(["seed", "replicate", "injection"]) for c in ("Deployed", "Repaired"))
        both = d["time_to_notice"].notna().to_numpy() & r["time_to_notice"].notna().to_numpy()
        x, y = d["time_to_notice"].to_numpy(float)[both], r["time_to_notice"].to_numpy(float)[both]
        by["_h1"] = {"pairs": int(both.sum()), "p": float(wilcoxon(x, y).pvalue) if both.sum() and (x != y).any() else 1.0,
                     "repaired_shorter": bool(np.median(y) < np.median(x)) if both.sum() else None}
        out[int(s)] = by
    return out


def median_case(timelines: dict, df: pd.DataFrame, seed: int, replicate: str, hour: int) -> dict:
    """The injection whose Deployed time to notice is the median one, with every condition's timeline."""
    d = df[(df["condition"] == "Deployed") & (df["seed"] == seed) & (df["replicate"] == replicate) & (df["s"] == PRIMARY_S)]
    d = d.dropna(subset=["time_to_notice"]).sort_values("time_to_notice")
    j = int(d.iloc[len(d) // 2]["injection"]) if len(d) else 0
    t0, _ = timelines["Deployed"][j]
    cases = {c: {"timeline": timelines[c][j][1],
                 "time_to_notice": (lambda x: None if pd.isna(x) else float(x))(
                     df[(df["condition"] == c) & (df["seed"] == seed) & (df["replicate"] == replicate)
                        & (df["s"] == PRIMARY_S) & (df["injection"] == j)]["time_to_notice"].iloc[0])}
             for c in timelines}
    return {"bin_seconds": BIN, "hour_seconds": hour, "attack_start": t0, "analyst_seconds_per_alert": PRIMARY_S,
            "conditions": cases}


def to_markdown(res: dict) -> str:
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    L = ["# Attack Night: minutes of attacker freedom", "",
         f"Generated on {res['generated']}. {res['features']} features ({feats}); seeds {', '.join(map(str, res['seeds']))}; "
         f"one hour of real household traffic ({res['evening_flows']:,} flows, untouched second evening) with a lab attack "
         f"campaign ({', '.join(f'{k}: {v} flows' for k, v in res['campaign_flows'].items())}) inserted at {INJECTIONS} random "
         "moments per seed and replicate. FIFO analyst. Rules in docs/PREREGISTRATION_ATTACK_NIGHT.md.", "",
         "| Analyst pace | Detector | Household alerts / hour | Time to notice, median (IQR) | Attack missed | Over before noticed |",
         "|---|---|---|---|---|---|"]
    fmt = lambda m: "—" if m is None else (f"{m * 60:.0f} s" if m < 1 else f"{m:.1f} min")  # noqa: E731
    for s, by in res["summary"].items():
        for cond in CONDITIONS:
            b = by[cond]
            L.append(f"| 1 per {s} s | {cond} | {b['household_alerts_per_hour']:.0f} | {fmt(b['median_minutes'])} "
                     f"({fmt(b['q25_minutes'])}–{fmt(b['q75_minutes'])}) | {b['missed']:.0%} | {b['over_before_noticed']:.0%} |")
    p = res["summary"][PRIMARY_S] if PRIMARY_S in res["summary"] else res["summary"][str(PRIMARY_S)]
    h1 = p["_h1"]
    L += ["", f"**H1 (1 alert per {PRIMARY_S} s):** Deployed {fmt(p['Deployed']['median_minutes'])} vs Repaired "
          f"{fmt(p['Repaired']['median_minutes'])}; Wilcoxon p = {h1['p']:.2g} over {h1['pairs']} paired injections: "
          + ("**confirmed**." if h1["repaired_shorter"] and h1["p"] < 0.05 else "**not confirmed**."),
          f"Per-seed medians (min): Deployed {p['Deployed']['per_seed_median_minutes']}, Repaired {p['Repaired']['per_seed_median_minutes']}.", "",
          f"**H2:** missed, Deployed {p['Deployed']['missed']:.0%} vs Repaired {p['Repaired']['missed']:.0%}.", "",
          f"**H3:** port-scan and SYN-burst flows flagged: Repaired {p['Repaired']['dismissed_types_flagged']:.0%}, "
          f"Poisoned {p['Poisoned']['dismissed_types_flagged']:.0%}, Poisoned + gate {p['Poisoned, gated']['dismissed_types_flagged']:.0%}; "
          f"missed {p['Repaired']['missed']:.0%} / {p['Poisoned']['missed']:.0%} / {p['Poisoned, gated']['missed']:.0%}.", "",
          "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
