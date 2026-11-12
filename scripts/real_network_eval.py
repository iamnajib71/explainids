"""Does the adaptation recipe hold on a real network, not just the benchmark and the lab?

Usage:
  python scripts/real_network_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --lab-profile data/lab/run_20261025T051701Z/flows_labelled.csv \
      --fit-sessions data/sensor/<earlier-day sessions> --study data/sensor/study_wifi_<date>.json \
      --results docs/results/real_network.md

Design. The same training conditions as `service_aware_eval.py` (source dataset, optional k labelled
target attack flows per class plus 1,000 target benign flows, optional benign service flows) are scored
on passive captures of a real network in normal use. Local flows offered to training come only from the
`--fit-sessions` (recorded on an earlier day); every evaluated flow comes from the study's blocks, so no
evaluated flow, block or day is ever trained on. Conditions:

  source only / both environments          references
  few-shot                                 the condition whose service regression the lab exposed
  few-shot + lab service flows             does the lab-derived repair transfer to a real network?
  few-shot + local flows                   the repair using the site's own earlier traffic
  source only + local flows                local benign traffic without any target labels

The captured network is in ordinary use and no attack traffic was generated on it, so every alert is
treated as a false alert. That assumption is unverified; the per-block rates are therefore upper bounds
on false alerts. Intervals are a bootstrap over blocks (flows within a block are not independent).
Target detection on the benchmark test split is reported alongside so a gain on one axis cannot hide a
loss on the other. Accuracy is never reported (project rule 4). Outputs hold aggregates only: no
addresses or per-flow records.
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
from service_aware_eval import (  # noqa: E402
    ENV_SPECIFIC, fit_detector, few_shot, load_dataset, load_profile, score_attacks, split_profile)

from ids import SEED  # noqa: E402
from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope, LocalRefit, TwoEnvelope  # noqa: E402
from ids.repair import local_sample, service_key, triage_sample, uncertainty_sample  # noqa: E402
from ids.scoring import align_columns  # noqa: E402

N_BOOT = 2000


def load_session(folder: Path, feats: list[str]) -> pd.DataFrame:
    """A validated sensor session as benign-assumed flows in the model schema, with its time span."""
    raw = pd.read_csv(folder / "validated.csv", low_memory=False)
    aligned, missing = align_columns(raw, feats)
    if missing:
        raise ValueError(f"{folder.name}: {len(missing)} features missing, e.g. {missing[:5]}")
    numeric = aligned[feats].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    out = numeric.loc[valid].reset_index(drop=True)
    if "Dst Port" not in out and "Dst Port" in aligned:
        # Kept as metadata for per-service sampling and reporting even when it is not a model feature.
        out["Dst Port"] = pd.to_numeric(aligned.loc[valid, "Dst Port"], errors="coerce").fillna(-1).astype(int).to_numpy()
    out[LABEL_COL] = BENIGN
    times = pd.to_datetime(aligned.loc[valid, "Timestamp"], errors="coerce", dayfirst=True) \
        if "Timestamp" in aligned else pd.Series(dtype="datetime64[ns]")
    span = (times.max() - times.min()).total_seconds() if times.notna().sum() > 1 else float("nan")
    out.attrs["span_seconds"] = span
    out.attrs["session"] = folder.name
    return out


def study_sessions(study: Path) -> list[Path]:
    record = json.loads(study.read_text(encoding="utf-8"))
    root = study.parent
    return [root / b["session"] for b in record["blocks"]
            if b.get("returncode") == 0 and b.get("session") and (root / b["session"] / "validated.csv").is_file()]


def block_bootstrap(alerts: np.ndarray, flows: np.ndarray, seed: int = SEED) -> tuple[float, float]:
    """95% interval for the pooled alert rate, resampling whole blocks."""
    if len(flows) < 2:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(flows), size=(N_BOOT, len(flows)))
    rates = alerts[idx].sum(axis=1) / np.maximum(flows[idx].sum(axis=1), 1)
    return float(np.quantile(rates, 0.025)), float(np.quantile(rates, 0.975))


def service_concentration(port_flows: dict[str, int], port_alerts: dict[str, int],
                          min_flows: int = 5, collapsed: float = 0.8) -> dict:
    """How service-shaped the false alerts are.

    A service (destination port with at least `min_flows` flows) is *collapsed* when the model flags
    at least `collapsed` of its flows. If most alerts sit in collapsed services, the failure is a
    whole-service misclassification that a small per-service benign sample can repair; if they are
    spread thinly, it is not.
    """
    total = sum(port_alerts.values())
    eligible = {p: n for p, n in port_flows.items() if n >= min_flows}
    rates = {p: port_alerts.get(p, 0) / n for p, n in eligible.items()}
    hit = [p for p, r in rates.items() if r >= collapsed]
    return {"services": len(eligible), "collapsed_services": sorted(hit),
            "alerts_in_collapsed": sum(port_alerts.get(p, 0) for p in hit),
            "share_in_collapsed": sum(port_alerts.get(p, 0) for p in hit) / total if total else None,
            "services_clean": sum(r == 0 for r in rates.values()),
            "services_partial": sum(0 < r < collapsed for r in rates.values())}


def score_blocks(det, blocks: list[pd.DataFrame], feats: list[str]) -> dict:
    alerts, flows, called, by_port, port_flows = [], [], {}, {}, {}
    for block in blocks:
        X = block[feats]
        pred = det.predict(X)
        flagged = (pred != BENIGN) | det.anomaly(X)[1]
        alerts.append(int(flagged.sum()))
        flows.append(len(block))
        for k, v in pd.Series(pred[pred != BENIGN]).value_counts().items():
            called[str(k)] = called.get(str(k), 0) + int(v)
        grouped = pd.Series(flagged, index=block.index).groupby(service_key(block))
        for port, hit in grouped.sum().items():
            port_flows[str(port)] = port_flows.get(str(port), 0) + int(grouped.size()[port])
            if hit:
                by_port[str(port)] = by_port.get(str(port), 0) + int(hit)
    a, n = np.array(alerts), np.array(flows)
    hours = sum(b.attrs.get("span_seconds", float("nan")) for b in blocks) / 3600
    top = dict(sorted(by_port.items(), key=lambda kv: -kv[1])[:8])
    return {"blocks": len(blocks), "flows": int(n.sum()), "alerts": int(a.sum()),
            "rate": float(a.sum() / n.sum()), "rate_ci": list(block_bootstrap(a, n)),
            "block_rates": [round(x / y, 4) for x, y in zip(a, n)],
            "alerts_per_hour": float(a.sum() / hours) if hours > 0 else None,
            "called": called, "alerts_by_port": top,
            "service_concentration": service_concentration(port_flows, by_port)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--lab-profile", required=True)
    ap.add_argument("--fit-sessions", nargs="+", required=True, help="earlier sessions that may contribute training flows")
    ap.add_argument("--study", type=Path, required=True, help="study record whose blocks are evaluated")
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--local-benign", type=int, default=1000)
    ap.add_argument("--portable", action="store_true",
                    help="drop destination port and TCP initial-window/segment-size features (the shortcut set)")
    ap.add_argument("--results", default="docs/results/real_network.md")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",")]

    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    lab = load_profile(args.lab_profile, feats)
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    eval_dirs = study_sessions(args.study)
    if set(Path(s).name for s in args.fit_sessions) & set(p.name for p in eval_dirs):
        raise SystemExit("fit and evaluation sessions overlap")
    blocks = [load_session(p, feats) for p in eval_dirs]
    blocks = [b for b in blocks if len(b)]
    if not blocks:
        raise SystemExit("no evaluable blocks in the study")
    rows: list[dict] = []

    def run(config: str, train: pd.DataFrame, val: pd.DataFrame, **meta):
        det = fit_detector(train, val, feats, args.model)
        row = {"config": config, **meta, "training_rows": int(len(train)),
               "target_test": score_attacks(det, tgt["test"], feats),
               "real_network": score_blocks(det, blocks, feats)}
        rows.append(row)
        rn = row["real_network"]
        print(f"{config} {meta}: target det {row['target_test']['macro_detection']:.3f} | "
              f"real alerts {rn['alerts']}/{rn['flows']} = {rn['rate']:.3f}", flush=True)
        return det

    def rescore(config: str, det, **meta) -> None:
        """Score an already-trained model under a different anomaly rule; no retraining."""
        row = {"config": config, **meta, "target_test": score_attacks(det, tgt["test"], feats),
               "real_network": score_blocks(det, blocks, feats)}
        rows.append(row)
        rn = row["real_network"]
        print(f"{config} {meta}: target det {row['target_test']['macro_detection']:.3f} | "
              f"real alerts {rn['alerts']}/{rn['flows']} = {rn['rate']:.3f}", flush=True)

    def local_threshold(config: str, det, **meta) -> None:
        """Same model, anomaly threshold re-set on the site's earlier traffic at the 1% budget."""
        det = copy.deepcopy(det)
        det.tune_anomaly_threshold(fit_pool[feats])
        rescore(config, det, **meta)

    source = run("source only", src["train"], src["val"])
    local_threshold("source only + local anomaly threshold", source)
    rescore("source only + two-envelope anomaly", TwoEnvelope(source, fit_pool[feats]))
    rescore("source only + exemplar envelope", ExemplarEnvelope(source, fit_pool[feats]))
    src_benign = src["train"][src["train"][LABEL_COL] == BENIGN].sample(
        min(20000, int((src["train"][LABEL_COL] == BENIGN).sum())), random_state=SEED)
    rescore("source only + local refit anomaly", LocalRefit(source, src_benign, fit_pool[feats]))
    run("both environments", pd.concat([src["train"], tgt["train"]]), pd.concat([src["val"], tgt["val"]]))
    n = args.service_flows
    for seed in seeds:
        labels = few_shot(tgt, args.k, args.local_benign, seed)
        lab_fit, _ = split_profile(lab, n, seed)
        local = local_sample(fit_pool, n, seed)
        det = run("few-shot", pd.concat([src["train"], labels]), src["val"], seed=seed)
        triaged, confirmed = triage_sample(det, fit_pool, feats, n, seed)
        run(f"few-shot + {n} lab service flows", pd.concat([src["train"], labels, lab_fit]), src["val"], seed=seed)
        run(f"few-shot + {n} local flows", pd.concat([src["train"], labels, local]), src["val"], seed=seed)
        repaired = run(f"few-shot + {n} triaged local flows", pd.concat([src["train"], labels, triaged]),
                       src["val"], seed=seed, triaged_alerts=confirmed)
        local_threshold(f"few-shot + {n} triaged local flows + local anomaly threshold", repaired, seed=seed)
        rescore(f"few-shot + {n} triaged local flows + two-envelope anomaly",
                TwoEnvelope(repaired, fit_pool[feats]), seed=seed)
        rescore(f"few-shot + {n} triaged local flows + exemplar envelope",
                ExemplarEnvelope(repaired, fit_pool[feats]), seed=seed)
        rescore(f"few-shot + {n} triaged local flows + local refit anomaly",
                LocalRefit(repaired, src_benign, fit_pool[feats]), seed=seed)
        uncertain = uncertainty_sample(det, fit_pool, feats, n)
        unsure = run(f"few-shot + {n} uncertain local flows", pd.concat([src["train"], labels, uncertain]),
                     src["val"], seed=seed)
        rescore(f"few-shot + {n} uncertain local flows + exemplar envelope",
                ExemplarEnvelope(unsure, fit_pool[feats]), seed=seed)
        run(f"source only + {n} local flows", pd.concat([src["train"], local]), src["val"], seed=seed)

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "source": src["name"],
           "features": len(feats), "portable": args.portable,
           "target": tgt["name"], "k": args.k, "service_flows": n, "seeds": seeds,
           "fit_sessions": len(args.fit_sessions), "fit_pool_flows": int(len(fit_pool)),
           "eval_blocks": len(blocks), "eval_flows": int(sum(len(b) for b in blocks)),
           "eval_hours": sum(b.attrs["span_seconds"] for b in blocks) / 3600,
           "runs": rows, "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"results in {out}")


def to_markdown(res: dict) -> str:
    md = ["# Real-network evaluation", "",
          f"Generated on {res['generated']}. Model {res['model'].upper()}; source {res['source']}, target "
          f"{res['target']}, k = {res['k']} labelled target flows per attack class. Evaluated on "
          f"{res['eval_flows']:,} flows in {res['eval_blocks']} capture blocks ({res['eval_hours']:.2f} h of "
          f"observed traffic) from a network in ordinary use. Local training flows come only from "
          f"{res['fit_sessions']} sessions recorded on an earlier day ({res['fit_pool_flows']} flows). No attack "
          "traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is "
          "unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean "
          f"and range over {len(res['seeds'])} seeds.", "",
          "| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |",
          "|---|---|---|---|---|"]
    frame = pd.DataFrame(res["runs"])
    for config, group in frame.groupby("config", sort=False):
        det = [r["macro_detection"] for r in group["target_test"]]
        rate = [r["rate"] for r in group["real_network"]]
        lo = min(r["rate_ci"][0] for r in group["real_network"])
        hi = max(r["rate_ci"][1] for r in group["real_network"])
        aph = [r["alerts_per_hour"] for r in group["real_network"] if r["alerts_per_hour"] is not None]
        spread = f" (seeds {min(rate):.1%}–{max(rate):.1%})" if len(rate) > 1 else ""
        md.append(f"| {config} | {np.mean(det):.3f} | {np.mean(rate):.1%}{spread} | {lo:.1%}–{hi:.1%} | "
                  f"{np.mean(aph):,.0f} |" if aph else f"| {config} | {np.mean(det):.3f} | {np.mean(rate):.1%}"
                  f"{spread} | {lo:.1%}–{hi:.1%} | n/a |")
    md += ["", "## Where the alerts fall", "",
           "A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows "
           "alert. The share of alerts inside collapsed services measures how service-shaped the failure is.", "",
           "| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | "
           "Predicted classes |", "|---|---|---|---|"]
    for config, group in frame.groupby("config", sort=False):
        ports: dict[str, int] = {}
        called: dict[str, int] = {}
        for r in group["real_network"]:
            for k, v in r["alerts_by_port"].items():
                ports[k] = ports.get(k, 0) + v
            for k, v in r["called"].items():
                called[k] = called.get(k, 0) + v
        p = ", ".join(f"{k}: {v}" for k, v in sorted(ports.items(), key=lambda kv: -kv[1])[:6]) or "none"
        c = ", ".join(f"{k}: {v}" for k, v in sorted(called.items(), key=lambda kv: -kv[1])[:5]) or "none"
        conc = [r["service_concentration"] for r in group["real_network"]]
        inside = sum(x["alerts_in_collapsed"] for x in conc)
        total = sum(r["alerts"] for r in group["real_network"])
        share = f"{inside / total:.0%} ({inside}/{total})" if total else "no alerts"
        md.append(f"| {config} | {share} | {p} | {c} |")
    md += ["", "Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.",
           "", f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    main()
