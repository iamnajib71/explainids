"""Condense the research experiments into web/data/research.json for the console's Findings view.

Usage: python scripts/build_research_summary.py [--results docs/results] [--out web/data/research.json]

Reads the JSON written by cross_dataset_eval.py (RQ1), shap_stability_eval.py (RQ2),
unseen_attack_eval.py (RQ3) and real_network_eval.py --portable (both real-network evenings). A missing experiment becomes null and the console shows it as pending,
so the page never displays a number that no script produced.
"""
import argparse
import json
from pathlib import Path

import numpy as np

SHORT = {"cicids2017": "2017", "csecicids2018": "2018"}
SOURCES = [
    ("Cantone et al., 2024", "https://doi.org/10.1109/ACCESS.2024.3472907"),
    ("D'hooge et al., 2022", "https://doi.org/10.1007/978-3-031-09484-2_2"),
    ("Liu et al., 2022", "https://doi.org/10.1109/CNS56114.2022.9947235"),
    ("Lin & Wang, 2025", "https://doi.org/10.3390/risks13120238"),
    ("Sarhan et al., 2023", "https://doi.org/10.1007/s10207-023-00676-0"),
    ("Lundberg et al., 2020", "https://doi.org/10.1038/s42256-019-0138-9"),
    ("MITRE ATT&CK", "https://attack.mitre.org/"),
]


def load(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def transfer(res: dict | None) -> dict | None:
    if not res:
        return None
    runs = {(r["source"], r["target"]): r for r in res["runs"]["all"]}
    names = [d["name"] for d in res["datasets"]]
    same = [runs[(t, t)]["classifier"]["recall"] for t in names]
    other = [runs[(next(s for s in names if s != t), t)]["classifier"]["recall"] for t in names]
    worst = min(range(len(names)), key=lambda i: other[i])
    src = next(s for s in names if s != names[worst])
    f1 = {f"{SHORT[s]}→{SHORT[t]}": round(r["macro_common"]["f1"], 3) for (s, t), r in runs.items()}
    return {
        "question": "Does it work on a new network?",
        "headline": f"{other[worst]:.0%}", "label": f"of attack flows caught after moving {SHORT[src]} → {SHORT[names[worst]]}",
        "targets": [SHORT[t] for t in names], "same": same, "other": other,
        "tip": (f"Trained on one corrected CIC dataset, tested on the other (LGBM, all {len(res['features']['all'])} shared "
                f"features). Bars show attack recall; macro F1 over the {len(res['common_classes'])} common classes: "
                + ", ".join(f"{k} {v:.2f}" for k, v in f1.items())
                + ". Dropping environment-specific features (port, TCP windows) did not help. Source: docs/results/cross_dataset.md"),
    }


def calibration_note(res: dict) -> str:
    """One sentence on benign-only local calibration for the worst transfer direction."""
    d = min(res["directions"], key=lambda x: x["deployed"]["macro_detection"])
    thr = [r for r in d["runs"] if r["rule"] == "local threshold" and r["size"] == min(res["sizes"])]
    fpr = float(np.mean([r["fpr"] for r in thr]))
    det = float(np.mean([r["macro_detection"] for r in thr]))
    return (f"Calibrating on {min(res['sizes']):,} local benign flows cuts false alarms from "
            f"{d['deployed']['fpr']:.1%} to {fpr:.1%} but class-balanced detection falls from "
            f"{d['deployed']['macro_detection']:.0%} to {det:.0%}: calibration controls alert burden, not detection. "
            "Source: docs/results/local_calibration.md")


def few_shot_note(res: dict) -> str:
    """What the matched-control run shows about limited-label adaptation and legitimate services."""
    runs, benign = res["runs"], [k for k in res["runs"][0]["tests"] if k.startswith("benign:")]
    if not benign:                                      # legacy run without service profiles
        shots = [r for r in runs if r.get("target")]
        k = min(r["k"] for r in shots)
        return (f"Adding {k} labelled local flows per attack type raises target detection, but the run measured "
                "no legitimate-service traffic. Source: docs/results/multi_env.md")

    def rates(run):
        return [run["tests"][b]["fpr"] for b in benign]

    def pick(prefix, k=None):
        return [r for r in runs if r["config"].startswith(prefix) and (k is None or r.get("k") == k)]

    both = pick("both environments")[0]
    base = next(r for r in runs if r["config"].startswith("single") and "2017" in r["config"])
    shots = [r for r in runs if r["config"].startswith("few-shot") and r.get("k")]
    worst_k = max(r["k"] for r in shots)
    worst = [r for r in shots if r["k"] == worst_k]
    only = [r for r in runs if r["config"].startswith("target-only")]
    target = next(k for k in both["tests"] if k not in ("2017", "lab") and not k.startswith("benign:"))
    span = [min(min(rates(r)) for r in worst), max(max(rates(r)) for r in worst)]
    return (f"Training on both environments reaches {both['tests'][target]['macro_detection']:.1%} detection on "
            f"{target} and halves legitimate-service false alerts to {min(rates(both)):.0%}, against "
            f"{max(rates(base)):.0%} for the source-only model. Limited local labels raise detection but push "
            f"service false alerts to {span[0]:.0%}-{span[1]:.0%} at k={worst_k}, and the matched target-only "
            f"control flags up to {max(max(rates(r)) for r in only):.0%} of legitimate flows. "
            "Source: docs/results/multi_env_matched.md")


def service_aware_note(res: dict) -> str:
    """Whether a few local benign service flows repair the adaptation's service regression."""
    runs = res["runs"]
    worst = max((r for r in runs if r.get("service_flows") == 0 and r.get("k")),
                key=lambda r: r["held_in_profile"]["fpr"])
    repaired = [r for r in runs if r.get("service_flows") and r.get("k") == worst["k"]]
    if not repaired:
        return ""
    best = min(repaired, key=lambda r: r["service_flows"])
    hi = best["held_in_profile"]
    return (f"Adding {best.get('service_added', best['service_flows'])} local benign service flows cuts false alerts on legitimate traffic "
            f"from {worst['held_in_profile']['fpr']:.0%} to {hi['fpr']:.0%} observed (95% interval to "
            f"{max(hi['fpr_ci']):.1%}) while detection holds at {best['target_test']['macro_detection']:.3f}, "
            "and it transfers to a service configuration never trained on. "
            "Source: docs/results/service_aware.md")


FEW_SHOT, REPAIRED = "few-shot", "few-shot + 30 triaged local flows + exemplar envelope"
LAB, UNCERTAIN = "few-shot + 30 lab service flows", "few-shot + 30 uncertain local flows + exemplar envelope"


def _mean(res: dict, config: str, key: str) -> float:
    return float(np.mean([r["real_network"][key] for r in res["runs"] if r["config"] == config]))


def _blocks_lower(res: dict, config: str, reference: str) -> tuple[int, int, float]:
    """Blocks where config alerts less than reference (seed-averaged), blocks compared, two-sided sign-test p."""
    from scipy.stats import binomtest
    rates = {c: np.mean([r["real_network"]["block_rates"] for r in res["runs"] if r["config"] == c], axis=0)
             for c in (config, reference)}
    d = rates[config] - rates[reference]
    lower, n = int((d < 0).sum()), int((d != 0).sum())
    return lower, n, float(binomtest(lower, n, 0.5).pvalue) if n else 1.0


def real_network(day1: dict | None, day2: dict | None) -> dict | None:
    """Local repair on a home network in ordinary use: day 1 examined, day 2 pre-registered (shortcut-free features)."""
    evenings = [(name, res) for name, res in (("Evening 1", day1), ("Evening 2, pre-registered", day2)) if res]
    if not evenings:
        return None
    last = evenings[-1][1]
    before, after = _mean(last, FEW_SHOT, "alerts_per_hour"), _mean(last, REPAIRED, "alerts_per_hour")
    det = {c: np.mean([r["target_test"]["macro_detection"] for r in last["runs"] if r["config"] == c]) for c in (FEW_SHOT, REPAIRED)}
    tests = "; ".join(f"{name}: lower in {lo}/{n} blocks (sign test p = {p:.4f})"
                      for name, res in evenings for lo, n, p in [_blocks_lower(res, REPAIRED, FEW_SHOT)])
    lab_lo, lab_n, _ = _blocks_lower(last, LAB, FEW_SHOT)
    tri_lo, tri_n, _ = _blocks_lower(last, REPAIRED, UNCERTAIN)
    return {"question": "Does the repair hold on a real network?", "headline": f"−{1 - after / before:.0%}",
            "label": f"alerts per hour, {before:.0f} → {after:.0f}, on an evening fixed in advance",
            "evenings": [name for name, _ in evenings],
            "before": [_mean(res, FEW_SHOT, "rate") for _, res in evenings],
            "after": [_mean(res, REPAIRED, "rate") for _, res in evenings],
            "tip": (f"Home WiFi in ordinary use, {last['eval_flows']:,} flows in {last['eval_blocks']} five-minute blocks; "
                    "nothing was attacked, so every alert counts as a false alert (an upper bound). Few-shot model "
                    "(k = 50) against the same model repaired with 30 analyst-triaged local flows and a local model of "
                    f"normal traffic, fitted only on an earlier evening; port and TCP-window features removed. {tests}. "
                    f"Benchmark detection {det[FEW_SHOT]:.3f} → {det[REPAIRED]:.3f}. 30 lab service flows instead: lower "
                    f"in only {lab_lo}/{lab_n} blocks. Triage beat least-confident selection in {tri_lo}/{tri_n} blocks. "
                    "Source: docs/results/real_network_day2_portable.md, docs/PREREGISTRATION_DAY2.md")}


def unseen(res: dict | None, log_res: dict | None, other: dict | None = None) -> dict | None:
    if not res:
        return None
    rows = sorted(res["results"], key=lambda r: -r["unseen"]["either"])
    med = float(np.median([r["unseen"]["either"] for r in rows]))
    tip = (f"Each attack class removed from training in turn ({res['dataset']}, {len(rows)} classes); bars show how much "
           "of it still raised an alert. Isolation Forest threshold set for 1% false alarms on validation benign traffic.")
    if log_res:
        log_med = float(np.median([r["unseen"]["either"] for r in log_res["results"]]))
        tip += f" With signed-log features for the Isolation Forest the median is {log_med:.0%}."
    if other:
        other_med = float(np.median([r["unseen"]["either"] for r in other["results"]]))
        tip += f" On {other['dataset']} the median is {other_med:.0%}."
    return {"question": "Can it catch attacks it never saw?", "headline": f"{med:.0%}",
            "label": "median detection of an unseen attack type",
            "classes": [{"class": r["class"], "either": r["unseen"]["either"], "classifier": r["unseen"]["classifier"]}
                        for r in rows],
            "tip": tip + f" Source: docs/results/unseen_{res['dataset']}.md"}


def stability(res: dict | None) -> dict | None:
    if not res or res["local"]["overall"]["median"] is None:
        return None
    per = res["local"]["per_predicted_class"]
    classes = sorted(({"class": c, "median": v["median"]} for c, v in per.items() if v["count"] and c != "BENIGN"),
                     key=lambda x: -x["median"])
    skipped, total = res["local"]["skipped_prediction_changes"], res["local"]["total_pairs"]
    return {"question": "Do explanations stay the same?", "headline": f"{res['local']['overall']['median']:.2f}",
            "label": f"median top-{res['k']} SHAP overlap across {len(res['seeds'])} training seeds",
            "classes": classes,
            "tip": (f"Same {res['explained_flows']} test attack flows explained by models trained with different seeds; "
                    f"overlap 1 = identical top-{res['k']} features, 0 = none shared (0.67 = 4 of 5 shared). {skipped:,} of {total:,} flow pairs "
                    f"skipped because the prediction changed. Source: docs/results/shap_stability_{res['dataset']}.md")}


def attack_night(portable: dict | None, full: dict | None) -> dict | None:
    """Minutes an inserted lab attack waits behind the alert queue (one alert reviewed per minute)."""
    if not portable:
        return None
    def at60(res):
        s = res["summary"]["60"]
        return {c: {"minutes": s[c]["median_minutes"], "alerts_per_hour": s[c]["household_alerts_per_hour"]}
                for c in ("Deployed", "Repaired", "Poisoned", "Poisoned, gated")}
    return {"portable": at60(portable), "all_features": at60(full) if full else None,
            "p": portable["summary"]["60"]["_h1"]["p"], "injections": portable["summary"]["60"]["_h1"]["pairs"],
            "dismissed_types_flagged": {c: portable["summary"]["60"][c]["dismissed_types_flagged"]
                                        for c in ("Repaired", "Poisoned", "Poisoned, gated")}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="docs/results")
    ap.add_argument("--dataset", default="cicids2017", help="dataset shown for RQ2 and RQ3")
    ap.add_argument("--out", default="web/data/research.json")
    args = ap.parse_args()
    r = Path(args.results)
    out = {"transfer": transfer(load(r / "cross_dataset.json")),
           "stability": stability(load(r / f"shap_stability_{args.dataset}.json")),
           "unseen": unseen(load(r / f"unseen_{args.dataset}.json"), load(r / f"unseen_{args.dataset}_log.json"),
                            next((load(f) for f in sorted(r.glob("unseen_*.json"))
                                  if args.dataset not in f.stem and not f.stem.endswith("_log")), None)),
           "real": real_network(load(r / "real_network_portable.json"), load(r / "real_network_day2_portable.json")),
           "attack_night": attack_night(load(r / "attack_night_portable.json"), load(r / "attack_night.json")),
           "sources": [{"label": label, "url": url} for label, url in SOURCES]}
    calib = load(r / "local_calibration.json")
    if out["transfer"] and calib:
        out["transfer"]["tip"] += " " + calibration_note(calib)
    multi = load(r / "multi_env_matched.json") or load(r / "multi_env.json")
    if out["transfer"] and multi:
        out["transfer"]["tip"] += " " + few_shot_note(multi)
    repair = load(r / "service_aware.json")
    if out["transfer"] and repair:
        note = service_aware_note(repair)
        if note:
            out["transfer"]["tip"] += " " + note
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"wrote {args.out}: " + ", ".join(f"{k}={'ok' if v else 'pending'}" for k, v in out.items() if k != "sources"))


if __name__ == "__main__":
    main()
